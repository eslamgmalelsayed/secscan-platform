import { createApp } from 'vue';
import App from './App.vue';
import './style.css';

// Apply the saved theme before mount to avoid a flash. Light is the default.
const saved = localStorage.getItem('secscan.theme');
document.documentElement.dataset.theme = saved === 'dark' ? 'dark' : 'light';

createApp(App).mount('#app');
