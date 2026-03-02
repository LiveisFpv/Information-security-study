import { createRouter, createWebHistory } from 'vue-router'
import HomeView from '../views/HomeView.vue'
import DesView from '../views/DesView.vue'
import RsaView from '@/views/RsaView.vue'
import SignatureView from '@/views/SignatureView.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'home',
      component: HomeView,
    },
    {
      path: '/des',
      name: 'des',
      component: DesView,
    },
    {
      path:'/rsa',
      name: 'rsa',
      component: RsaView,
    },
    {
      path: '/signature',
      name: 'signature',
      component: SignatureView,
    },
  ],
})

export default router
