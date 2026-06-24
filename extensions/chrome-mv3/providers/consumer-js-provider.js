import { scanText } from "../redaction-rules.js";
import { decideRisk } from "../risk-decision.js";

export function createConsumerJsProvider() {
    return {
        name: "consumer_js",
        async check(request) {
            const findings = scanText(request && request.text);
            return decideRisk(request, findings);
        },
    };
}
