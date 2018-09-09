import Vue from 'vue'
import Router from 'vue-router'
import Main from '@/components/Main'
import Login from '@/components/Login'

Vue.use(Router)
let routes = [{
    path: '/',
    name: '首页',
    component: Main
  },
  {
    path: '/login',
    name: '登录',
    component: Login
  }
]

const router = new Router({
  routes: routes
})

router.beforeEach((to, from, next) => {
  if (to.path == '/login') {
    sessionStorage.removeItem('Authorization')
  }

  let token = sessionStorage.getItem('Authorization')
  if (!token && to.path != '/login') {
    next({
      path: '/login'
    })
    return
  }
  next()
})

export default router;
