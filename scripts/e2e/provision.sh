#!/usr/bin/env bash
# Create the tenant fixtures the e2e flows need. Idempotent - safe to re-run
# against a stack that is already provisioned.
#
#   sender.test   verified, sending    + an active DKIM key
#   inbound.test  verified, receiving  + a domain-match route to the webhook sink
#
# Domain verification normally requires live DNS (SPF/DKIM/MX lookups), which
# .test can never satisfy. Rather than weaken the API, the fixture flips the
# status directly in the throwaway compose database.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

domain_id() {
    api GET /v1/domains | python3 -c "
import json,sys
n=sys.argv[1]
print(next((d['id'] for d in json.load(sys.stdin)['data'] if d['domain_name']==n), ''))
" "$1"
}

ensure_domain() {
    local name="$1" sending="$2" receiving="$3" id
    id="$(domain_id "$name")"
    if [ -n "$id" ]; then
        info "domain $name exists ($id)"
    else
        id="$(api POST /v1/domains -d "{\"domain_name\":\"$name\",\"use_for_sending\":$sending,\"use_for_receiving\":$receiving}" \
              | jqf "d['data']['id']")"
        [ -n "$id" ] || { fail "could not create domain $name"; return 1; }
        info "created domain $name ($id)"
    fi
    echo "$id"
}

main() {
    info "provisioning against $API_BASE"

    local send_id recv_id
    send_id="$(ensure_domain "$SEND_DOMAIN" true false)"
    recv_id="$(ensure_domain "$RECV_DOMAIN" false true)"

    # .test can never pass real DNS verification; mark verified in-place.
    dc exec -T postgres psql -U sentio -d sentio -q -c \
        "UPDATE domains
            SET status='verified', verified_at=now(),
                spf_status='verified', dkim_status='verified', mx_status='verified'
          WHERE domain_name IN ('$SEND_DOMAIN','$RECV_DOMAIN');" >/dev/null
    info "marked $SEND_DOMAIN and $RECV_DOMAIN verified"

    # DKIM key on the sending domain, so outbound exercises the signing path
    # instead of logging "no active DKIM key found" and sending unsigned.
    local have_key
    have_key="$(api GET "/v1/domains/$send_id/dkim-keys" \
                | jqf "sum(1 for k in d['data'] if k.get('status')=='active')" || echo 0)"
    if [ "${have_key:-0}" -gt 0 ]; then
        info "active DKIM key already present on $SEND_DOMAIN"
    else
        api POST "/v1/domains/$send_id/dkim-keys" -d "{\"selector\":\"$DKIM_SELECTOR\"}" >/dev/null
        info "created DKIM key $DKIM_SELECTOR on $SEND_DOMAIN"
    fi

    # Inbound route: anything @inbound.test is POSTed to the webhook sink.
    local have_route
    have_route="$(api GET "/v1/tenants/$TENANT_ID/inbound-routes" \
                  | jqf "sum(1 for r in d['data'] if r['pattern']=='$RECV_DOMAIN')" || echo 0)"
    if [ "${have_route:-0}" -gt 0 ]; then
        info "inbound route for $RECV_DOMAIN already present"
    else
        api POST "/v1/tenants/$TENANT_ID/inbound-routes" -d "{
            \"match_type\":\"domain\",
            \"pattern\":\"$RECV_DOMAIN\",
            \"webhook_url\":\"http://webhook-sink:8080/inbound\",
            \"priority\":100,
            \"llm_classify\":false,
            \"auto_respond\":false
        }" >/dev/null
        info "created inbound route for $RECV_DOMAIN"
    fi

    info "provisioning complete"
}

main "$@"
