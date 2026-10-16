import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5050/api',
})

// Attach Bearer token to all outgoing requests if authenticated
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('threattrail_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Automatically handle expired/invalid tokens (401)
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      const path = window.location.pathname
      if (!path.includes('/login') && !path.includes('/register')) {
        localStorage.removeItem('threattrail_token')
        localStorage.removeItem('threattrail_user')
      }
    }
    return Promise.reject(error)
  }
)

export default api
