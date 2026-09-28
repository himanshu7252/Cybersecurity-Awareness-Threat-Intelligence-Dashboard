/**
 * Cybersecurity Dashboard REST API Client
 * Author: Defensive Cybersecurity Engineering Team
 */

const API = {
  baseUrl: '/api',

  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const defaultHeaders = {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    };

    const config = {
      ...options,
      headers: { ...defaultHeaders, ...options.headers }
    };

    try {
      const response = await fetch(url, config);
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || `HTTP Error ${response.status}`);
      }
      return data;
    } catch (err) {
      console.error(`API Error [${endpoint}]:`, err);
      throw err;
    }
  },

  // Dashboard & Executive
  async getStats() {
    const res = await this.request('/dashboard/stats');
    return res.data;
  },

  async getTrends() {
    const res = await this.request('/dashboard/trends');
    return res.data;
  },

  async getExecutiveSummary() {
    const res = await this.request('/executive/summary');
    return res.data;
  },

  // Threats & IOCs
  async getThreats(params = {}) {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') query.append(k, v);
    });
    const res = await this.request(`/threats?${query.toString()}`);
    return res.data;
  },

  async getThreatById(id) {
    const res = await this.request(`/threats/${encodeURIComponent(id)}`);
    return res.data;
  },

  async getThreatCorrelation(id) {
    const res = await this.request(`/threats/${encodeURIComponent(id)}/correlation`);
    return res.data;
  },

  async addThreatNote(threatId, analystName, note) {
    const res = await this.request(`/threats/${encodeURIComponent(threatId)}/notes`, {
      method: 'POST',
      body: JSON.stringify({ analyst_name: analystName, note })
    });
    return res.data;
  },

  // Indicator Search & Validation
  async searchIndicator(query) {
    const res = await this.request(`/indicators/search?q=${encodeURIComponent(query)}`);
    return res.data;
  },

  async validateIndicator(indicator) {
    const res = await this.request('/indicators/validate', {
      method: 'POST',
      body: JSON.stringify({ indicator })
    });
    return res.data;
  },

  // Alerts
  async getAlerts(status = '') {
    const query = status ? `?status=${encodeURIComponent(status)}` : '';
    const res = await this.request(`/alerts${query}`);
    return res.data;
  },

  async updateAlertStatus(alertId, newStatus, note = '') {
    const res = await this.request(`/alerts/${encodeURIComponent(alertId)}/status`, {
      method: 'PUT',
      body: JSON.stringify({ status: newStatus, note })
    });
    return res.data;
  },

  // Vulnerabilities
  async getVulnerabilities(params = {}) {
    const query = new URLSearchParams(params).toString();
    const res = await this.request(`/vulnerabilities?${query}`);
    return res.data;
  },

  async getVulnerabilityById(cveId) {
    const res = await this.request(`/vulnerabilities/${encodeURIComponent(cveId)}`);
    return res.data;
  },

  // Awareness Modules & Quiz
  async getAwarenessModules(category = '') {
    const query = category ? `?category=${encodeURIComponent(category)}` : '';
    const res = await this.request(`/awareness/modules${query}`);
    return res.data;
  },

  async getQuizQuestions(examMode = false) {
    const res = await this.request(`/quiz?exam_mode=${examMode}`);
    return res.data;
  },

  async submitQuiz(answers, userId = 'student_analyst') {
    const res = await this.request('/quiz/submit', {
      method: 'POST',
      body: JSON.stringify({ answers, user_id: userId })
    });
    return res.data;
  }
};
