//! Geolocation Module
//!
//! This module provides IP geolocation using the IP-API service. Results are cached
//! to reduce redundant lookups and improve performance. It also provides utilities
//! to clear and check the cache.
use crate::error::{DmarcError, Result};
use crate::models::IpGeoInfo;
use ipgeolocate::{Locator, Service};
use std::collections::HashMap;
use std::sync::Mutex;
use lazy_static::lazy_static;
use tracing::{info, warn};
lazy_static! {
    static ref IP_CACHE: Mutex<HashMap<String, IpGeoInfo>> = Mutex::new(HashMap::new());
}
/// GeoLookup provides asynchronous IP geolocation with caching.
#[allow(dead_code)]
pub struct GeoLookup;
#[allow(dead_code)]
impl GeoLookup {
    /// Looks up the geolocation for the given IP address.
    /// First checks the cache; if not found, performs a lookup via IP-API.
    pub async fn lookup_ip(ip: &str) -> Result<IpGeoInfo> {
        if let Some(cached_info) = IP_CACHE.lock().unwrap().get(ip) {
            return Ok(cached_info.clone());
        }
        match Locator::get(ip, Service::IpApi).await {
            Ok(location) => {
                let geo_info = IpGeoInfo {
                    country: location.country,
                    city: Some(location.city),
                    latitude: location.latitude.parse::<f64>().unwrap_or(0.0),
                    longitude: location.longitude.parse::<f64>().unwrap_or(0.0),
                    asn: None, // IP-API free tier doesn't provide ASN
                    organization: None,
                };
                IP_CACHE.lock().unwrap().insert(ip.to_string(), geo_info.clone());
                info!("Successful geolocation lookup for IP: {}", ip);
                Ok(geo_info)
            }
            Err(e) => {
                warn!("Geolocation lookup failed for IP {}: {}", ip, e);
                Err(DmarcError::Geolocation(e.to_string()))
            }
        }
    }
    /// Clears the IP geolocation cache.
    pub fn clear_cache() {
        IP_CACHE.lock().unwrap().clear();
        info!("Geolocation cache cleared");
    }
    /// Returns the current size of the IP geolocation cache.
    pub fn cache_size() -> usize {
        IP_CACHE.lock().unwrap().len()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio;
    #[tokio::test]
    async fn test_ip_lookup() {
        let result = GeoLookup::lookup_ip("8.8.8.8").await;
        assert!(result.is_ok());
        let geo_info = result.unwrap();
        assert!(!geo_info.country.is_empty());
        assert!(geo_info.latitude != 0.0);
        assert!(geo_info.longitude != 0.0);
    }
    #[test]
    fn test_cache() {
        let test_info = crate::models::IpGeoInfo {
            country: "Test Country".to_string(),
            city: Some("Test City".to_string()),
            latitude: 0.0,
            longitude: 0.0,
            asn: None,
            organization: None,
        };
        IP_CACHE.lock().unwrap().insert("1.1.1.1".to_string(), test_info);
        assert_eq!(GeoLookup::cache_size(), 1);
        GeoLookup::clear_cache();
        assert_eq!(GeoLookup::cache_size(), 0);
    }
}
