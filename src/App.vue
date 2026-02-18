<script setup lang="ts">
import { RouterLink, RouterView } from 'vue-router'
</script>

<template>
  <div class="layout">
    <header class="header">
      <nav class="nav">
        <RouterLink to="/" class="nav-link">Классические шифры</RouterLink>
        <RouterLink to="/des" class="nav-link">DES (ECB)</RouterLink>
        <RouterLink to="/rsa" class="nav-link">RSA</RouterLink>
      </nav>
    </header>
    <RouterView />
  </div>
</template>

<style scoped>
.layout {
  min-height: 100vh;
}

.header {
  width: 100%;
  border-bottom: 1px solid #d4d8df;
  background: #f8fbff;
  padding: 10px 16px;
}

.nav {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.nav-link {
  border: 1px solid #c6d3e8;
  border-radius: 8px;
  padding: 6px 10px;
  color: #1b3a6c;
  text-decoration: none;
}

.nav-link.router-link-exact-active {
  background: #dcecff;
  border-color: #5a93ed;
}
</style>
