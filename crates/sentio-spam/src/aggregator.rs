use sentio_core::config::SpamConfig;
use sentio_core::traits::SpamAction;

/// Maps a numeric spam score to a `SpamAction` based on configured thresholds.
///
/// Threshold ordering (enforced by config validation):
///   `score_greylist` < `score_add_header` < `score_reject`
pub fn score_to_action(score: f64, config: &SpamConfig) -> SpamAction {
    if score >= config.score_reject {
        SpamAction::Reject
    } else if score >= config.score_add_header {
        SpamAction::AddHeader
    } else if score >= config.score_greylist {
        SpamAction::Greylist
    } else {
        SpamAction::Accept
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> SpamConfig {
        SpamConfig::default()
    }

    #[test]
    fn below_greylist_is_accept() {
        let config = default_config();
        assert_eq!(score_to_action(0.0, &config), SpamAction::Accept);
        assert_eq!(score_to_action(3.9, &config), SpamAction::Accept);
    }

    #[test]
    fn at_greylist_threshold() {
        let config = default_config();
        assert_eq!(score_to_action(4.0, &config), SpamAction::Greylist);
        assert_eq!(score_to_action(5.9, &config), SpamAction::Greylist);
    }

    #[test]
    fn at_add_header_threshold() {
        let config = default_config();
        assert_eq!(score_to_action(6.0, &config), SpamAction::AddHeader);
        assert_eq!(score_to_action(11.9, &config), SpamAction::AddHeader);
    }

    #[test]
    fn at_reject_threshold() {
        let config = default_config();
        assert_eq!(score_to_action(12.0, &config), SpamAction::Reject);
        assert_eq!(score_to_action(100.0, &config), SpamAction::Reject);
    }

    #[test]
    fn negative_score_is_accept() {
        let config = default_config();
        assert_eq!(score_to_action(-5.0, &config), SpamAction::Accept);
    }

    #[test]
    fn custom_thresholds() {
        let config = SpamConfig {
            score_greylist: 2.0,
            score_add_header: 5.0,
            score_reject: 10.0,
            ..Default::default()
        };
        assert_eq!(score_to_action(1.9, &config), SpamAction::Accept);
        assert_eq!(score_to_action(2.0, &config), SpamAction::Greylist);
        assert_eq!(score_to_action(5.0, &config), SpamAction::AddHeader);
        assert_eq!(score_to_action(10.0, &config), SpamAction::Reject);
    }
}
