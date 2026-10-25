@id("action-policy/analyst-intern-actions/rule/1")
permit (
    principal in Muistamo::Template::"analyst-intern",
    action == Muistamo::Action::"sharepoint.read",
    resource is Muistamo::Tool
);

@id("action-policy/analyst-intern-actions/rule/2")
permit (
    principal in Muistamo::Template::"analyst-intern",
    action == Muistamo::Action::"email.draft",
    resource is Muistamo::Tool
);

@id("action-policy/analyst-intern-actions/rule/3")
permit (
    principal in Muistamo::Template::"analyst-intern",
    action == Muistamo::Action::"email.send",
    resource is Muistamo::Tool
)
when { context.attributes has "recipients.allInternal" && context.attributes["recipients.allInternal"] == true };

@id("action-policy/analyst-intern-actions/rule/4")
forbid (
    principal in Muistamo::Template::"analyst-intern",
    action == Muistamo::Action::"email.send",
    resource is Muistamo::Tool
)
unless { context.attributes has "recipients.allInternal" && context.attributes["recipients.allInternal"] == true };

@id("action-policy/analyst-intern-actions/rule/5")
forbid (
    principal in Muistamo::Template::"analyst-intern",
    action == Muistamo::Action::"crm.update",
    resource is Muistamo::Tool
);

@id("link/analyst-intern-to-market-data")
permit (
    principal in Muistamo::Template::"analyst-intern",
    action == Muistamo::Action::"call",
    resource in Muistamo::Template::"market-data-agent"
)
when { ["get-quotes", "get-company-financials"].contains(context.skill) && ["public", "internal"].containsAll(context.dataClasses) && context.depth <= 1 && context.actFor == "same-user" };
