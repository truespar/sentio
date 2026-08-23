use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;

use sentio_abuse::DnsLookup;
use sentio_core::traits::SpamRule;

static URL_REGEX: OnceLock<Regex> = OnceLock::new();

fn url_regex() -> &'static Regex {
    URL_REGEX.get_or_init(|| Regex::new(r#"https?://[^\s<>"']+"#).unwrap())
}

/// URI blacklist scorer.
///
/// Extracts URLs from the message body, resolves their domains against
/// configured URIBL zones, and produces a `SpamRule` for each listing.
pub struct UriblScorer<D: DnsLookup + Clone> {
    resolver: D,
    zones: Vec<String>,
}

impl<D: DnsLookup + Clone> UriblScorer<D> {
    pub fn new(resolver: D, zones: Vec<String>) -> Self {
        Self { resolver, zones }
    }

    /// Extract URLs from the message body, check their domains against URIBL
    /// zones, and return any matching rules (+4.0 per listing).
    pub async fn check(&self, raw_message: &[u8]) -> Vec<SpamRule> {
        let body = extract_body(raw_message);
        let domains = extract_domains(&body);

        if domains.is_empty() || self.zones.is_empty() {
            return vec![];
        }

        let mut rules = Vec::new();
        let mut seen = HashSet::new();

        for domain in &domains {
            for zone in &self.zones {
                let query = format!("{domain}.{zone}");
                if seen.contains(&query) {
                    continue;
                }
                seen.insert(query.clone());

                if self.resolver.lookup_a(&query).await.unwrap_or(false) {
                    rules.push(SpamRule {
                        name: format!(
                            "URIBL_{}_{}",
                            zone.replace('.', "_").to_uppercase(),
                            domain.replace('.', "_").to_uppercase()
                        ),
                        score: 4.0,
                        description: format!("Domain {domain} listed on {zone}"),
                    });
                }
            }
        }

        rules
    }
}

/// Extract the body from a raw message.
fn extract_body(raw: &[u8]) -> String {
    let raw_str = String::from_utf8_lossy(raw);
    if let Some(pos) = raw_str.find("\r\n\r\n") {
        raw_str[pos + 4..].to_string()
    } else if let Some(pos) = raw_str.find("\n\n") {
        raw_str[pos + 2..].to_string()
    } else {
        String::new()
    }
}

/// Extract unique domains from URLs found in the body text.
fn extract_domains(body: &str) -> Vec<String> {
    let mut domains = HashSet::new();

    for mat in url_regex().find_iter(body) {
        if let Ok(parsed) = url::Url::parse(mat.as_str()) {
            if let Some(host) = parsed.host_str() {
                let domain = host.to_ascii_lowercase();
                // Skip IP addresses
                if !domain.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    domains.insert(domain);
                }
            }
        }
    }

    domains.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct MockDns {
        listed_queries: Arc<Mutex<HashSet<String>>>,
    }

    impl MockDns {
        fn new() -> Self {
            Self {
                listed_queries: Arc::new(Mutex::new(HashSet::new())),
            }
        }

        fn list(&self, query: &str) {
            self.listed_queries
                .lock()
                .unwrap()
                .insert(query.to_string());
        }
    }

    impl DnsLookup for MockDns {
        fn lookup_a<'a>(
            &'a self,
            name: &'a str,
        ) -> impl Future<Output = Result<bool, String>> + Send + 'a {
            let listed = self.listed_queries.lock().unwrap().contains(name);
            std::future::ready(Ok(listed))
        }

        fn reverse_lookup<'a>(
            &'a self,
            _ip: &'a IpAddr,
        ) -> impl Future<Output = Result<bool, String>> + Send + 'a {
            std::future::ready(Ok(true))
        }
    }

    fn make_message(body: &str) -> Vec<u8> {
        format!("From: test@example.com\r\n\r\n{body}").into_bytes()
    }

    #[tokio::test]
    async fn listed_domain_produces_rule() {
        let dns = MockDns::new();
        dns.list("evil.com.multi.uribl.com");

        let scorer = UriblScorer::new(dns, vec!["multi.uribl.com".into()]);
        let msg = make_message("Check out https://evil.com/page for details");

        let rules = scorer.check(&msg).await;
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].score, 4.0);
        assert!(rules[0].description.contains("evil.com"));
    }

    #[tokio::test]
    async fn clean_domain_no_rules() {
        let dns = MockDns::new();
        let scorer = UriblScorer::new(dns, vec!["multi.uribl.com".into()]);
        let msg = make_message("Visit https://example.com for info");

        let rules = scorer.check(&msg).await;
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn multiple_urls_deduplicated() {
        let dns = MockDns::new();
        dns.list("evil.com.multi.uribl.com");

        let scorer = UriblScorer::new(dns, vec!["multi.uribl.com".into()]);
        let msg = make_message("Link1: https://evil.com/page1\nLink2: https://evil.com/page2");

        let rules = scorer.check(&msg).await;
        // Same domain, same zone → only one rule
        assert_eq!(rules.len(), 1);
    }

    #[tokio::test]
    async fn no_urls_no_rules() {
        let dns = MockDns::new();
        let scorer = UriblScorer::new(dns, vec!["multi.uribl.com".into()]);
        let msg = make_message("Just a plain text message with no links.");

        let rules = scorer.check(&msg).await;
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn empty_zones_no_rules() {
        let dns = MockDns::new();
        let scorer = UriblScorer::new(dns, vec![]);
        let msg = make_message("Visit https://evil.com for info");

        let rules = scorer.check(&msg).await;
        assert!(rules.is_empty());
    }

    #[test]
    fn extract_domains_from_body() {
        let body = "Go to https://example.com/path and also http://test.org/page";
        let domains = extract_domains(body);
        assert!(domains.contains(&"example.com".to_string()));
        assert!(domains.contains(&"test.org".to_string()));
    }

    #[test]
    fn extract_domains_skips_ips() {
        let body = "Visit http://192.168.1.1/admin";
        let domains = extract_domains(body);
        assert!(domains.is_empty());
    }
}
