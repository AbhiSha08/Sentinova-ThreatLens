import axios from 'axios';

const apiClient = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

/**
 * Fetch Executive CTI Dashboard Summary (cached for 300s on backend)
 */
export const fetchExecutiveSummary = async () => {
  const response = await apiClient.get('/analytics/executive-summary');
  return response.data;
};

/**
 * Fetch Paginated and Filterable IOC list for SOC Analyst view
 * @param {Object} params - Query parameters (page, page_size, severity, ioc_type, mitre_technique, search, sort_by, sort_order)
 */
export const fetchIndicators = async (params = {}) => {
  const cleanParams = {};
  Object.keys(params).forEach((key) => {
    if (params[key] !== undefined && params[key] !== null && params[key] !== '' && params[key] !== 'ALL') {
      cleanParams[key] = params[key];
    }
  });
  const response = await apiClient.get('/indicators', { params: cleanParams });
  return response.data;
};

/**
 * Fast Single IOC Enrichment Lookup with transparent score breakdown
 * @param {string} q - Exact or prefix indicator value
 */
export const lookupIndicator = async (q) => {
  const response = await apiClient.get('/indicators/lookup', {
    params: { q: q.trim() },
  });
  return response.data;
};

/**
 * Bulk IOC Triage for SOC analysts (up to 50 IOCs)
 * @param {string[]} indicatorsList - Array of raw indicator strings
 */
export const bulkLookupIndicators = async (indicatorsList) => {
  const response = await apiClient.post('/indicators/bulk-lookup', {
    indicators: indicatorsList,
  });
  return response.data;
};

/**
 * Construct direct download URL for SIEM export (CSV or JSON)
 * @param {Object} params - Active filter parameters
 * @param {'csv'|'json'} format - Target export format
 */
export const exportIndicatorsUrl = (params = {}, format = 'csv') => {
  const searchParams = new URLSearchParams();
  searchParams.set('format', format);

  Object.keys(params).forEach((key) => {
    if (
      params[key] !== undefined &&
      params[key] !== null &&
      params[key] !== '' &&
      params[key] !== 'ALL' &&
      !['page', 'page_size', 'sort_by', 'sort_order'].includes(key)
    ) {
      searchParams.set(key, params[key]);
    }
  });

  return `/api/v1/indicators/export?${searchParams.toString()}`;
};

/**
 * Fetch Health and Sync Status of all registered Threat Feeds
 */
export const fetchFeedsStatus = async () => {
  const response = await apiClient.get('/feeds/');
  return response.data;
};

/**
 * Trigger immediate ingestion sync across all threat intelligence feeds
 */
export const triggerFeedSync = async () => {
  const response = await apiClient.post('/feeds/sync');
  return response.data;
};

/**
 * Check backend liveness and version
 */
export const fetchBackendHealth = async () => {
  const response = await apiClient.get('/health');
  return response.data;
};

export default apiClient;
