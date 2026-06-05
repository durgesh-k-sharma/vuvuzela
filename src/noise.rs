use crate::types::NoiseParams;
use rand::Rng;

/// Sample from a truncated Laplace distribution: max(0, Laplace(mu, b)).
///
/// Uses the inverse CDF method. The Laplace CDF is:
///   F(x) = 0.5 * exp((x - mu) / b)       for x < mu
///   F(x) = 1 - 0.5 * exp(-(x - mu) / b)  for x >= mu
///
/// We sample u ~ Uniform(0, 1) and invert:
///   x = mu - b * sign(u - 0.5) * ln(1 - 2 * |u - 0.5|)
///
/// Then truncate at 0: max(0, x).
pub fn sample_truncated_laplace(params: &NoiseParams) -> f64 {
    let mut rng = rand::thread_rng();
    loop {
        let u: f64 = rng.gen();
        let sample = params.mu - params.b * (u - 0.5).signum() * (1.0 - 2.0 * (u - 0.5).abs()).ln();
        if sample >= 0.0 {
            return sample;
        }
    }
}

/// Sample the number of single-access noise requests for a round.
/// n1 = ceil(max(0, Laplace(mu, b)))
pub fn sample_n1(params: &NoiseParams) -> u64 {
    sample_truncated_laplace(params).ceil() as u64
}

/// Sample the number of pair-access noise requests for a round.
/// n2 = ceil(max(0, Laplace(mu/2, b/2)))
pub fn sample_n2(params: &NoiseParams) -> u64 {
    let pair_params = NoiseParams {
        mu: params.mu / 2.0,
        b: params.b / 2.0,
    };
    sample_truncated_laplace(&pair_params).ceil() as u64
}

/// Compute the expected total noise requests per server per round.
pub fn expected_noise_per_round(params: &NoiseParams) -> f64 {
    params.mu + params.mu / 2.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_laplace_non_negative() {
        let params = NoiseParams { mu: 100.0, b: 10.0 };
        for _ in 0..1000 {
            let sample = sample_truncated_laplace(&params);
            assert!(sample >= 0.0, "sample was negative: {}", sample);
        }
    }

    #[test]
    fn truncated_laplace_mean() {
        let params = NoiseParams { mu: 100.0, b: 10.0 };
        let n = 10_000;
        let sum: f64 = (0..n).map(|_| sample_truncated_laplace(&params)).sum();
        let mean = sum / n as f64;
        // Truncated Laplace mean should be close to mu (within 5% for large mu)
        assert!(
            mean > params.mu * 0.95 && mean < params.mu * 1.05,
            "mean {} not close to mu {}",
            mean,
            params.mu
        );
    }

    #[test]
    fn sample_n1_non_negative() {
        let params = NoiseParams { mu: 100.0, b: 10.0 };
        for _ in 0..100 {
            let n = sample_n1(&params);
            assert!(n < 10_000, "n1 {} seems too large", n);
        }
    }

    #[test]
    fn sample_n2_non_negative() {
        let params = NoiseParams { mu: 100.0, b: 10.0 };
        for _ in 0..100 {
            let n = sample_n2(&params);
            assert!(n < 10_000, "n2 {} seems too large", n);
        }
    }

    #[test]
    fn paper_conversation_params() {
        let params = NoiseParams::default_conversation();
        let expected = expected_noise_per_round(&params);
        assert!((expected - 450_000.0).abs() < 1.0);
    }

    #[test]
    fn paper_dialing_params() {
        let params = NoiseParams::default_dialing();
        let expected = expected_noise_per_round(&params);
        assert!((expected - 19_500.0).abs() < 1.0);
    }
}
