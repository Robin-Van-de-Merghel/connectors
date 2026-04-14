import base64
import datetime
import io
import json
import os
import re
import time

import cairosvg
import cmarkgfm
from cmarkgfm import Options as cmarkgfmOptions
from jinja2 import Environment, FileSystemLoader
from pycti import OpenCTIConnectorHelper, StixCyberObservableTypes
from pygal_maps_world.i18n import COUNTRIES
from pygal_maps_world.maps import World
from weasyprint import HTML

from export_report_pdf.config import ConnectorConfig

CMARKGFM_OPTIONS = (
    cmarkgfmOptions.CMARK_OPT_GITHUB_PRE_LANG
    | cmarkgfmOptions.CMARK_OPT_FOOTNOTES
    | cmarkgfmOptions.CMARK_OPT_TABLE_PREFER_STYLE_ATTRIBUTES
)

# ---------------------------------------------------------------------------
# Callout block definitions
# Maps GitHub alert types -> (css_class, display_label)
# ---------------------------------------------------------------------------
_CALLOUT_TYPES: dict[str, tuple[str, str]] = {
    "NOTE": ("callout-note", "Note"),
    "INFO": ("callout-note", "Info"),
    "TIP": ("callout-note", "Tip"),
    "IMPORTANT": ("callout-critical", "Important"),
    "CRITICAL": ("callout-critical", "Critical Action"),
    "WARNING": ("callout-warning", "Warning"),
    "CAUTION": ("callout-warning", "Caution"),
}

# cmarkgfm renders  > [!TYPE]\n> body  as <blockquote><p>[!TYPE]\nbody</p>…</blockquote>
_CALLOUT_RE = re.compile(
    r"<blockquote>\s*<p>\[!([A-Z]+)\]\n?(.*?)</p>(.*?)</blockquote>",
    re.DOTALL | re.IGNORECASE,
)

# Observable types surfaced as "impacted assets" in the dashboard panel
_ASSET_OBSERVABLE_TYPES = {
    "IPv4-Addr",
    "IPv6-Addr",
    "Domain-Name",
    "Hostname",
    "Network-Traffic",
    "Url",
}


def _replace_callout(match: re.Match) -> str:
    """Regex replacement: rewrite a callout blockquote as a styled div."""
    callout_type = match.group(1).upper()
    first_line = match.group(2).strip()
    rest_content = match.group(3).strip()

    css_class, label = _CALLOUT_TYPES.get(
        callout_type, ("callout-note", callout_type.capitalize())
    )

    body_parts = []
    if first_line:
        body_parts.append(f"<p>{first_line}</p>")
    if rest_content:
        body_parts.append(rest_content)
    body_html = "\n".join(body_parts)

    return (
        f'<div class="{css_class}">'
        f'<div class="callout-label">{label}</div>'
        f'<div class="callout-body">{body_html}</div>'
        f"</div>"
    )


def _process_callouts(html: str) -> str:
    """
    Post-process cmarkgfm HTML to convert GitHub-style alert blockquotes
    (> [!NOTE], > [!WARNING], etc.) into styled callout <div> blocks.
    Call this after cmarkgfm.github_flavored_markdown_to_html().
    """
    return _CALLOUT_RE.sub(_replace_callout, html)


def _build_dashboard_context(entities: dict, observables: dict) -> dict:
    """
    Compute dashboard summary metrics from already-classified entities/observables.
    Returns a dict ready to merge into the Jinja2 template context.
    """
    total_iocs = sum(len(v) for v in observables.values())

    def _count_entity(key: str) -> int:
        for k, v in entities.items():
            if k.lower().replace("-", "_") == key.lower():
                return len(v)
        return 0

    impacted_assets: list[str] = []
    for obs_type, obs_list in observables.items():
        if obs_type in _ASSET_OBSERVABLE_TYPES:
            for obs in obs_list:
                val = obs.get("observable_value", "")
                if val and val not in impacted_assets:
                    impacted_assets.append(val)

    return {
        "total_iocs": total_iocs,
        "malware_count": _count_entity("malware"),
        "attack_pattern_count": _count_entity("attack_pattern"),
        "incident_count": _count_entity("incident"),
        "impacted_assets": impacted_assets,
    }


class Connector:
    def __init__(self, config: ConnectorConfig, helper: OpenCTIConnectorHelper) -> None:
        self.config = config
        self.helper = helper
        self.current_dir = os.path.abspath(os.path.dirname(__file__)) + "/../"
        self._set_colors()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_readable_date_time(self, str_date_time: str) -> str:
        """Convert an ISO datetime string to a human-readable format."""
        dt = datetime.datetime.fromisoformat(str_date_time)
        return dt.strftime("%B %d, %I:%M%p")

    def _jinja_env(self) -> Environment:
        """Return a Jinja2 Environment pointing at self.current_dir."""
        return Environment(
            loader=FileSystemLoader(self.current_dir), finalize=self._finalize
        )

    def _render_pdf(self, html_string: str) -> bytes:
        """Render one HTML string to PDF bytes via WeasyPrint."""
        return HTML(
            string=html_string, base_url=f"{self.current_dir}/resources"
        ).write_pdf()

    def _merge_pdfs(self, *html_strings: str) -> bytes:
        """
        Render multiple HTML strings as separate WeasyPrint documents and
        concatenate all pages into a single PDF binary.
        """
        docs = [
            HTML(
                string=html, base_url=f"{self.current_dir}/resources"
            ).render()
            for html in html_strings
        ]
        all_pages: list = []
        for doc in docs:
            all_pages.extend(doc.pages)
        return docs[0].copy(all_pages).write_pdf()

    def _build_world_map_png(self, entities: dict) -> str | None:
        """
        Build a base64-encoded PNG world map of targeted countries from
        relationship entities. Returns a data-URI string or None if no
        valid targets are found.
        """
        if "relationship" not in entities:
            return None

        world_map = World()
        world_map.title = "Targeted Countries"
        targeted_countries: list[str] = []

        for relationship in entities["relationship"]:
            if (
                relationship.get("entity_type") == "targets"
                and relationship.get("relationship_type") == "targets"
                and relationship.get("to", {}).get("entity_type") == "Country"
            ):
                country_code = relationship["to"]["name"].lower()
                if not self._validate_country_code(country_code):
                    self.helper.log_warning(
                        f"{country_code} is not a supported country code, skipping..."
                    )
                    continue
                targeted_countries.append(country_code)

        if not targeted_countries:
            return None

        world_map.add("Targeted Countries", targeted_countries)
        svg_bytes = world_map.render()
        png_bytes = io.BytesIO()
        cairosvg.svg2png(bytestring=svg_bytes, write_to=png_bytes)
        base64_png = base64.b64encode(png_bytes.getvalue()).decode()
        return f"data:image/png;base64, {base64_png}"

    def _collect_entity(self, context: dict, entity: dict, obj_entity_type: str) -> None:
        """
        Classify a STIX entity into context["entities"] or context["observables"],
        applying indicator-only filtering and URL defanging as configured.
        Mutates context in place.
        """
        if obj_entity_type == "StixFile" or StixCyberObservableTypes.has_value(
            obj_entity_type
        ):
            if self.config.indicators_only and not entity.get("indicators"):
                self.helper.log_info(
                    f"Skipping {obj_entity_type} observable with value "
                    f"{entity.get('observable_value')} as it was not an Indicator."
                )
                return
            if obj_entity_type not in context["observables"]:
                context["observables"][obj_entity_type] = []
            if self.config.defang_urls and obj_entity_type == "Url":
                entity["observable_value"] = entity["observable_value"].replace(
                    "http", "hxxp", 1
                )
            context["observables"][obj_entity_type].append(entity)
        else:
            if obj_entity_type not in context["entities"]:
                context["entities"][obj_entity_type] = []
            context["entities"][obj_entity_type].append(entity)

    def _company_context(self) -> dict:
        """Return company address fields as a dict for template contexts."""
        return {
            "company_address_line_1": self.config.company_address_line_1,
            "company_address_line_2": self.config.company_address_line_2,
            "company_address_line_3": self.config.company_address_line_3,
            "company_phone_number": self.config.company_phone_number,
            "company_email": self.config.company_email,
            "company_website": self.config.company_website,
        }

    # ------------------------------------------------------------------
    # Message router
    # ------------------------------------------------------------------

    def _process_message(self, data: dict) -> str:
        file_name = data["file_name"]
        entity_id = data.get("entity_id")
        export_scope = data["export_scope"]
        main_filter = data.get("main_filter")
        entity_type = data["entity_type"]
        access_filter = data.get("access_filter")
        list_params = data.get("list_params")
        file_markings = data["file_markings"]

        if export_scope != "single":
            self._process_list(
                file_name,
                entity_id,
                entity_type,
                file_markings,
                main_filter,
                list_params,
                access_filter,
                export_scope,
            )
        elif entity_type == "Report":
            self._process_report(entity_id, file_name, file_markings, access_filter)
        elif entity_type in ("Case-Incident", "Case-Rfi", "Case-Rft"):
            self._process_case(
                entity_id, file_name, entity_type, file_markings, access_filter
            )
        elif entity_type == "Intrusion-Set":
            self._process_intrusion_set(entity_id, file_name, file_markings)
        elif entity_type == "Threat-Actor-Group":
            self._process_threat_actor_group(entity_id, file_name, file_markings)
        elif entity_type == "Threat-Actor-Individual":
            self._process_threat_actor_individual(entity_id, file_name, file_markings)
        elif entity_type == "Vulnerability":
            self._process_vulnerability(entity_id, file_name, file_markings)
        else:
            raise ValueError(
                f'This connector currently only handles the entity types: "Report", '
                f'"Intrusion-Set", "Threat-Actor-Group", "Threat-Actor-Individual", '
                f'"Case-Incident", "Case-Rfi", "Case-Rft", "Vulnerability", '
                f'not "{entity_type}".'
            )

        return "Export done"

    # ------------------------------------------------------------------
    # List export
    # ------------------------------------------------------------------

    def _process_list(
        self,
        file_name: str,
        entity_id: str | None,
        entity_type: str,
        file_markings: list,
        main_filter,
        list_params: dict | None,
        access_filter,
        export_scope: str,
    ) -> None:
        if export_scope == "selection":
            list_filters = "selected_ids"
            entity_data_sdo = self.helper.api_impersonate.stix_domain_object.list(
                filters=main_filter,
            )
            entity_data_sco = self.helper.api_impersonate.stix_cyber_observable.list(
                filters=main_filter
            )
            entity_data_scr = self.helper.api_impersonate.stix_core_relationship.list(
                filters=main_filter
            )
            entities_list = entity_data_sdo + entity_data_sco + entity_data_scr
        else:  # export_scope == 'query'
            list_params_filters = (
                list_params.get("filters") if list_params is not None else None
            )
            access_filter_content = (
                access_filter.get("filters") if access_filter is not None else None
            )
            if len(access_filter_content) != 0 and list_params_filters is not None:
                export_query_filter = {
                    "mode": "and",
                    "filterGroups": [list_params_filters, access_filter],
                    "filters": [],
                }
            elif len(access_filter_content) == 0:
                export_query_filter = list_params_filters
            else:
                export_query_filter = access_filter

            entities_list = self.helper.api_impersonate.stix2.export_entities_list(
                entity_type=entity_type,
                search=list_params.get("search"),
                filters=export_query_filter,
                orderBy=list_params.get("orderBy"),
                orderMode=list_params.get("orderMode"),
                getAll=True,
            )
            self.helper.log_info("Uploading: " + entity_type + " to " + file_name)
            list_filters = json.dumps(list_params)

        if entities_list is None:
            raise ValueError("An error occurred, the list is empty")

        list_marking = file_markings if len(file_markings) != 0 else None
        list_search = (
            list_params.get("search", "No search keyword")
            if list_params is not None
            else "No search keyword"
        )

        context: dict = {
            "list_name": "Export of " + entity_type,
            "list_search": list_search,
            "list_filters": str(main_filter),
            "list_marking": list_marking,
            "list_report_date": datetime.datetime.now().strftime("%b %d %Y"),
            **self._company_context(),
            "entities": {},
            "observables": {},
        }

        for entity in entities_list:
            self._collect_entity(context, entity, entity["entity_type"])

        env = self._jinja_env()
        html_string = env.get_template("resources/list.html").render(context)
        pdf_contents = self._render_pdf(html_string)

        self.helper.log_info(f"Uploading: {file_name}")
        if entity_type == "Stix-Cyber-Observable":
            self.helper.api.stix_cyber_observable.push_list_export(
                entity_id,
                entity_type,
                file_name,
                file_markings,
                pdf_contents,
                list_filters,
            )
        elif entity_type == "Stix-Core-Object":
            self.helper.api.stix_core_object.push_list_export(
                entity_id,
                entity_type,
                file_name,
                file_markings,
                pdf_contents,
                list_filters,
            )
        else:
            self.helper.api.stix_domain_object.push_list_export(
                entity_id,
                entity_type,
                file_name,
                file_markings,
                pdf_contents,
                list_filters,
            )

    # ------------------------------------------------------------------
    # Report export  (dashboard + content pages)
    # ------------------------------------------------------------------

    def _process_report(
        self,
        entity_id: str,
        file_name: str,
        file_markings: list,
        access_filter,
    ) -> None:
        """
        Process a Report entity and upload as a multi-page PDF.
          Page 2: dashboard.html  (Intelligence Summary)
          Page 3+: content.html  (Two-column threat analysis body)
        """
        report_dict = self.helper.api_impersonate.report.read(id=entity_id)
        content_query = '{report (id:"' + entity_id + '") {content}}'
        report_dict["content"] = (
            self.helper.api_impersonate.query(query=content_query)
        )["data"]["report"].get("content", "No content available.")

        report_marking_list = report_dict.get("objectMarking") or []
        report_marking_str = (
            report_marking_list[-1]["definition"] if report_marking_list else None
        )

        report_description = (
            report_dict.get("description") or "No description available."
        )
        report_description_html = cmarkgfm.github_flavored_markdown_to_html(
            report_description, CMARKGFM_OPTIONS
        )

        raw_content = report_dict.get("content") or "No content available."
        report_content_html = _process_callouts(
            cmarkgfm.github_flavored_markdown_to_html(raw_content, CMARKGFM_OPTIONS)
        )

        context: dict = {
            "report_name": report_dict["name"],
            "report_description": report_description_html,
            "report_content_html": report_content_html,
            "report_marking": report_marking_str,
            "report_confidence": report_dict["confidence"],
            "report_external_refs": [
                ref["url"] for ref in report_dict.get("externalReferences", [])
            ],
            "report_date": datetime.datetime.now().strftime("%b %d %Y"),
            "report_creator": (report_dict.get("createdBy") or {}).get("name", "N/A"),
            # Dashboard fields (enriched below after entity loop)
            "risk_level": None,
            "cvss_score": None,
            "exploitability": None,
            "analysis_start": None,
            "analysis_end": None,
            "total_pages": 3,
            "current_page": 2,
            **self._company_context(),
            "entities": {},
            "observables": {},
        }

        object_ids = [obj["id"] for obj in report_dict.get("objects", [])]
        if object_ids:
            export_filter = self.helper.api.stix2.prepare_id_filters_export(
                object_ids, access_filter
            )
            entities_list = (
                self.helper.api.opencti_stix_object_or_stix_relationship.list(
                    filters=export_filter
                )
            )
            for entity in entities_list:
                self._collect_entity(context, entity, entity["entity_type"])

        context.update(
            _build_dashboard_context(context["entities"], context["observables"])
        )

        env = self._jinja_env()
        html_dashboard = env.get_template("resources/dashboard.html").render(context)

        context["current_page"] = 3
        html_content = env.get_template("resources/content.html").render(context)

        pdf_contents = self._merge_pdfs(html_dashboard, html_content)

        self.helper.log_info(f"Uploading: {file_name}")
        self.helper.api.stix_domain_object.push_entity_export(
            entity_id=report_dict["id"],
            file_name=file_name,
            data=pdf_contents,
            file_markings=file_markings,
            mime_type="application/pdf",
        )

    # ------------------------------------------------------------------
    # Intrusion Set export
    # ------------------------------------------------------------------

    def _process_intrusion_set(
        self, entity_id: str, file_name: str, file_markings: list
    ) -> None:
        """Process an Intrusion Set entity and upload as PDF."""
        context: dict = {
            "entities": {},
            "target_map_country": None,
            "report_date": datetime.datetime.now().strftime("%b %d %Y"),
            **self._company_context(),
        }

        bundle = self.helper.api_impersonate.stix2.get_stix_bundle_or_object_from_entity_id(
            entity_type="Intrusion-Set", entity_id=entity_id, mode="full"
        )
        for obj in bundle["objects"]:
            reader_func = self._get_reader(obj["type"])
            if reader_func is None:
                self.helper.log_error(
                    f'Could not find a function to read entity with type "{obj["type"]}"'
                )
                continue
            time.sleep(0.3)
            entity_dict = reader_func(id=obj["id"])
            key = obj["type"].replace("-", "_")
            context["entities"].setdefault(key, []).append(entity_dict)

        context["target_map_country"] = self._build_world_map_png(context["entities"])

        env = self._jinja_env()
        html_string = env.get_template("resources/intrusion-set.html").render(context)
        pdf_contents = self._render_pdf(html_string)

        self.helper.log_info(f"Uploading: {file_name}")
        self.helper.api.stix_domain_object.push_entity_export(
            entity_id=entity_id,
            file_name=file_name,
            data=pdf_contents,
            file_markings=file_markings,
            mime_type="application/pdf",
        )

    # ------------------------------------------------------------------
    # Threat Actor Group export
    # ------------------------------------------------------------------

    def _process_threat_actor_group(
        self, entity_id: str, file_name: str, file_markings: list
    ) -> None:
        """Process a Threat Actor Group entity and upload as PDF."""
        context: dict = {
            "entities": {},
            "target_map_country": None,
            "report_date": datetime.datetime.now().strftime("%b %d %Y"),
            **self._company_context(),
        }

        bundle = self.helper.api_impersonate.stix2.get_stix_bundle_or_object_from_entity_id(
            entity_type="Threat-Actor-Group", entity_id=entity_id, mode="full"
        )
        for obj in bundle["objects"]:
            reader_func = self._get_reader(obj["type"])
            if reader_func is None:
                self.helper.log_error(
                    f'Could not find a function to read entity with type "{obj["type"]}"'
                )
                continue
            time.sleep(0.3)
            entity_dict = reader_func(id=obj["id"])
            key = obj["type"].replace("-", "_")
            context["entities"].setdefault(key, []).append(entity_dict)

        context["target_map_country"] = self._build_world_map_png(context["entities"])

        env = self._jinja_env()
        html_string = env.get_template("resources/threat-actor.html").render(context)
        pdf_contents = self._render_pdf(html_string)

        self.helper.log_info(f"Uploading: {file_name}")
        self.helper.api.stix_domain_object.push_entity_export(
            entity_id=entity_id,
            file_name=file_name,
            data=pdf_contents,
            file_markings=file_markings,
            mime_type="application/pdf",
        )

    # ------------------------------------------------------------------
    # Threat Actor Individual export
    # ------------------------------------------------------------------

    def _process_threat_actor_individual(
        self, entity_id: str, file_name: str, file_markings: list
    ) -> None:
        """Process a Threat Actor Individual entity and upload as PDF."""
        context: dict = {
            "entities": {},
            "target_map_country": None,
            "report_date": datetime.datetime.now().strftime("%b %d %Y"),
            **self._company_context(),
        }

        bundle = self.helper.api_impersonate.stix2.get_stix_bundle_or_object_from_entity_id(
            entity_type="Threat-Actor-Individual", entity_id=entity_id, mode="full"
        )
        for obj in bundle["objects"]:
            reader_func = self._get_reader(obj["type"])
            if reader_func is None:
                self.helper.log_error(
                    f'Could not find a function to read entity with type "{obj["type"]}"'
                )
                continue
            time.sleep(0.3)
            entity_dict = reader_func(id=obj["id"])
            key = obj["type"].replace("-", "_")
            context["entities"].setdefault(key, []).append(entity_dict)

        context["target_map_country"] = self._build_world_map_png(context["entities"])

        env = self._jinja_env()
        html_string = env.get_template("resources/threat-actor.html").render(context)
        pdf_contents = self._render_pdf(html_string)

        self.helper.log_info(f"Uploading: {file_name}")
        self.helper.api.stix_domain_object.push_entity_export(
            entity_id=entity_id,
            file_name=file_name,
            data=pdf_contents,
            file_markings=file_markings,
            mime_type="application/pdf",
        )

    # ------------------------------------------------------------------
    # Case export
    # ------------------------------------------------------------------

    def _process_case(
        self,
        entity_id: str,
        file_name: str,
        entity_type: str,
        file_markings: list,
        access_filter,
    ) -> None:
        """Process a Case container (Incident / Rfi / Rft) and upload as PDF."""
        if entity_type == "Case-Incident":
            case_dict = self.helper.api_impersonate.case_incident.read(id=entity_id)
        elif entity_type == "Case-Rfi":
            case_dict = self.helper.api_impersonate.case_rfi.read(id=entity_id)
        elif entity_type == "Case-Rft":
            case_dict = self.helper.api_impersonate.case_rft.read(id=entity_id)
        else:
            raise ValueError(f"Unrecognized entity_type: {entity_type}")

        content_query = '{case (id:"' + entity_id + '") {content}}'
        case_dict["content"] = (
            self.helper.api_impersonate.query(query=content_query)
        )["data"]["case"].get("content", "No content available.")

        case_marking_list = case_dict.get("objectMarking") or []
        case_marking_str = (
            case_marking_list[-1]["definition"] if case_marking_list else None
        )

        case_description = case_dict.get("description") or "No description available."
        case_description_html = cmarkgfm.github_flavored_markdown_to_html(
            case_description, CMARKGFM_OPTIONS
        )

        context: dict = {
            "case_name": case_dict["name"],
            "case_description": case_description_html,
            "case_content": case_dict["content"],
            "case_marking": case_marking_str,
            "case_confidence": case_dict["confidence"],
            "case_id": case_dict["id"],
            "case_external_refs": [
                ref["url"] for ref in case_dict.get("externalReferences", [])
            ],
            "case_report_date": datetime.datetime.now().strftime("%b %d %Y"),
            "tasks": case_dict["tasks"],
            "case_type": case_dict["entity_type"],
            "case_priority": case_dict["priority"],
            "case_severity": case_dict["severity"],
            **self._company_context(),
            "entities": {},
            "observables": {},
        }

        object_ids = [obj["id"] for obj in case_dict.get("objects", [])]
        if object_ids:
            export_filter = self.helper.api.stix2.prepare_id_filters_export(
                object_ids, access_filter
            )
            entities_list = (
                self.helper.api.opencti_stix_object_or_stix_relationship.list(
                    filters=export_filter
                )
            )
            for entity in entities_list:
                self._collect_entity(context, entity, entity["entity_type"])

        env = self._jinja_env()
        html_string = env.get_template("resources/case.html").render(context)
        pdf_contents = self._render_pdf(html_string)

        self.helper.log_info(f"Uploading: {file_name}")
        self.helper.api.stix_domain_object.push_entity_export(
            entity_id=entity_id,
            file_name=file_name,
            data=pdf_contents,
            file_markings=file_markings,
            mime_type="application/pdf",
        )

    # ------------------------------------------------------------------
    # Vulnerability export
    # ------------------------------------------------------------------

    def _process_vulnerability(
        self, entity_id: str, file_name: str, file_markings: list
    ) -> None:
        """Process a Vulnerability entity and upload as PDF."""
        context: dict = {
            "report_date": datetime.datetime.now().strftime("%b %d %Y"),
            **self._company_context(),
            "vulnerability": None,
            "softwares_impacted": [],
            "softwares_resolved": [],
            "courses_of_action": [],
            "infrastructures": [],
        }

        bundle = self.helper.api_impersonate.stix2.get_stix_bundle_or_object_from_entity_id(
            entity_type="Vulnerability", entity_id=entity_id, mode="full"
        )

        entities_grouped: dict = {
            etype: {e["id"]: e for e in bundle["objects"] if e["type"] == etype}
            for etype in {e["type"] for e in bundle["objects"]}
        }

        vulnerability = next(iter(entities_grouped["vulnerability"].values()))
        context["vulnerability"] = vulnerability
        context["marking_definitions"] = [
            entities_grouped["marking-definition"][ref]["name"]
            for ref in vulnerability.get("object_marking_refs", [])
        ]

        for relationship in entities_grouped.get("relationship", {}).values():
            src_type = relationship["source_ref"].split("--")[0]
            src = entities_grouped[src_type][relationship["source_ref"]]
            match relationship["relationship_type"], src_type:
                case "has", "software":
                    entry = f"{src['vendor']}-{src['name']}"
                    if "version" in src:
                        entry += f"-{src['version']}"
                    context["softwares_impacted"].append(entry)
                case "remediates", "software":
                    entry = f"{src['vendor']}-{src['name']}"
                    if "version" in src:
                        entry += f"-{src['version']}"
                    context["softwares_resolved"].append(entry)
                case "remediates", "course-of-action":
                    context["courses_of_action"].append(src["name"])
                case "has", "infrastructure":
                    context["infrastructures"].append(src["name"])

        env = self._jinja_env()
        html_string = env.get_template("resources/vulnerability.html").render(context)
        pdf_contents = self._render_pdf(html_string)

        self.helper.log_info(f"Uploading Vulnerability PDF: {file_name}")
        self.helper.api.stix_domain_object.push_entity_export(
            entity_id=entity_id,
            file_name=file_name,
            data=pdf_contents,
            file_markings=file_markings,
            mime_type="application/pdf",
        )

    # ------------------------------------------------------------------
    # Startup utilities
    # ------------------------------------------------------------------

    def _set_colors(self) -> None:
        """
        Substitute <primary_color> and <secondary_color> in all
        .css.template files and write the resulting .css files.
        """
        for root, _dirs, files in os.walk(self.current_dir):
            for file_name in files:
                if not file_name.endswith(".css.template"):
                    continue
                template_path = os.path.join(root, file_name)
                with open(template_path) as f:
                    css = f.read()
                css = css.replace("<primary_color>", self.config.primary_color)
                css = css.replace("<secondary_color>", self.config.secondary_color)
                out_path = os.path.join(root, file_name.replace(".template", ""))
                with open(out_path, "w") as f:
                    f.write(css)

    def _validate_country_code(self, country_code: str) -> bool:
        """Return True if country_code is a valid pygal country code."""
        return country_code in COUNTRIES

    def _finalize(self, data):
        """Jinja2 finalizer: suppress None values as 'N/A'."""
        return data if data is not None else "N/A"

    def _get_reader(self, entity_type: str):
        """
        Return the API reader function for a given STIX entity type string,
        or None if the type is not supported.
        """
        reader = {
            "stix-core-object": self.helper.api_impersonate.stix_core_object.read,
            "stix-domain-object": self.helper.api_impersonate.stix_domain_object.read,
            "attack-pattern": self.helper.api_impersonate.attack_pattern.read,
            "campaign": self.helper.api_impersonate.campaign.read,
            "event": self.helper.api_impersonate.event.read,
            "note": self.helper.api_impersonate.note.read,
            "observed-data": self.helper.api_impersonate.observed_data.read,
            "organization": self.helper.api_impersonate.identity.read,
            "opinion": self.helper.api_impersonate.opinion.read,
            "report": self.helper.api_impersonate.report.read,
            "grouping": self.helper.api_impersonate.grouping.read,
            "sector": self.helper.api_impersonate.identity.read,
            "system": self.helper.api_impersonate.identity.read,
            "course-of-action": self.helper.api_impersonate.course_of_action.read,
            "identity": self.helper.api_impersonate.identity.read,
            "indicator": self.helper.api_impersonate.indicator.read,
            "individual": self.helper.api_impersonate.identity.read,
            "infrastructure": self.helper.api_impersonate.infrastructure.read,
            "intrusion-set": self.helper.api_impersonate.intrusion_set.read,
            "malware": self.helper.api_impersonate.malware.read,
            "Malware-Analysis": self.helper.api_impersonate.malware_analysis.list,
            "threat-actor": self.helper.api_impersonate.threat_actor.read,
            "tool": self.helper.api_impersonate.tool.read,
            "channel": self.helper.api_impersonate.channel.read,
            "narrative": self.helper.api_impersonate.narrative.read,
            "language": self.helper.api_impersonate.language.read,
            "vulnerability": self.helper.api_impersonate.vulnerability.read,
            "incident": self.helper.api_impersonate.incident.read,
            "x-opencti-case-incident": self.helper.api_impersonate.case_incident.read,
            "case-incident": self.helper.api_impersonate.case_incident.read,
            "x-opencti-case-rfi": self.helper.api_impersonate.case_rfi.read,
            "case-rfi": self.helper.api_impersonate.case_rfi.read,
            "city": self.helper.api_impersonate.location.read,
            "country": self.helper.api_impersonate.location.read,
            "region": self.helper.api_impersonate.location.read,
            "position": self.helper.api_impersonate.location.read,
            "location": self.helper.api_impersonate.location.read,
            "relationship": self.helper.api_impersonate.stix_core_relationship.read,
        }
        return reader.get(entity_type.lower(), None)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        self.helper.listen(self._process_message)
