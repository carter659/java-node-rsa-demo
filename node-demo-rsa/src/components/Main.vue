<template>
<div class="hello">
  当前用户：{{user}}
</div>
</template>

<script>
export default {
  data() {
    return {
      user: null
    }
  },
  mounted() {
    this.$axios.get('/getUser').then(res => {
      this.user = res.data
    })
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>

</style>
