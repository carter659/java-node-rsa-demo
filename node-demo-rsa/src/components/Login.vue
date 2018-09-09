<template>
<div class="hello">
  <table>
    <tr>
      <td>
        用户名：
      </td>
      <td>
        <input type="text" v-model="form.account" />
      </td>
    </tr>
    <tr>
      <td>
        密码：
      </td>
      <td>
        <input type="password" v-model="form.password" />
      </td>
    </tr>
    <tr>
      <td>
        <input type="button" value="登录" @click="loginByEncrypt" />
      </td>
      <td>
        <font v-if="message">{{message}}</font>
      </td>
    </tr>
  </table>
</div>
</template>

<script>
import NodeRSA from 'node-rsa'

export default {
  data() {
    return {
      message: null,
      sessionId: null,
      publicKey: null,
      form: {
        account: null,
        password: null
      }
    }
  },
  methods: {
    //明文登录
    login() {
      this.message = null
      this.$axios.post('/login', this.form).then(res => {
        if (!res.data.success) {
          this.message = res.data.message
          return
        }
        let token = res.data.data
        sessionStorage.setItem('Authorization', token)
        this.$axios.defaults.headers.common['Authorization'] = token
        this.$router.push({
          path: '/'
        });
      })
    },
    //获取session公钥
    getSession() {
      this.$axios.get('/getSession', this.form).then(res => {
        this.sessionId = res.data.sessionId
        this.publicKey = res.data.publicKey
      })
    },
    //密文登录
    loginByEncrypt() {
      let key = new NodeRSA(this.publicKey)
      key.setOptions({
        encryptionScheme: 'pkcs1'
      })

      this.message = null
      let playload = key.encrypt(JSON.stringify(this.form), 'base64', 'utf8')
      let param = {
        sessionId: this.sessionId,
        playload: playload
      }
      this.$axios.post('/loginByEncrypt', param).then(res => {
        if (!res.data.success) {
          this.message = res.data.message
          return
        }
        let token = res.data.data
        sessionStorage.setItem('Authorization', token)
        this.$axios.defaults.headers.common['Authorization'] = token
        this.$router.push({
          path: '/'
        });
      })
    }
  },
  mounted() {
    this.getSession()
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>

</style>
