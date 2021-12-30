<template>
  <div class="HomePage">
    <h1>端口扫描器</h1>

    <el-form :inline="true" :model="formInline" class="demo-form-inline">

      <el-form-item label="Protocol">
        <el-select v-model="formInline.protocol" placeholder="tcp" style="width: 80px">
          <el-option label="tcp" value="tcp"></el-option>
          <el-option label="udp" value="udp"></el-option>
          <el-option label="icmp" value="icmp"></el-option>
        </el-select>
      <el-form-item label="IP" style="padding-left: 24px">
        <el-input v-model="formInline.ip" placeholder="192.168.1.1/24" style="width: 180px"></el-input>
      </el-form-item>
      <el-form-item label="Port" style="padding-left: 24px">
        <el-input v-model="formInline.port" placeholder="80" style="width: 120px"></el-input>
      </el-form-item>

      </el-form-item>
      <!-- <el-form-item>
        <el-button type="primary" @click="onSubmit">Scan</el-button>
      </el-form-item> -->
    </el-form>



    <div class='button' style="margin-top: 5px">
      <!-- <el-button @click="fetch()" type="primary">抓取</el-button> -->
      <el-button @click="scan()" type="primary" style="margin-right: 50px">扫描</el-button>
      <el-button @click="clear()" type="primary" style="margin-left: 50px">清除</el-button>
    </div>

    <template>
      <el-table
        :data="tableData"
        style="width: 100%;margin-top: 50px"
        :row-class-name="tableRowClassName"
        height="700">

        <el-table-column
          fixed
          prop="protocol"
          label="Protocol"
          width="150">
        </el-table-column>
        <el-table-column
          prop="ip"
          label="IP"
          width="200">
        </el-table-column>
        <el-table-column
          prop="port"
          label="Port"
          width="120">
        </el-table-column>
        <el-table-column
          prop="state"
          label="State"
          width="120">
        </el-table-column>
      </el-table>
    </template>
  </div>
</template>

<script>
export default {
  name: 'HomePage',
  data () {
    return {
      scan_url: this.$http.defaults.baseURL + "scan",
      formInline: {
        protocol: '',
        ip: '',
        port: ''
      },
      tableData: [],
      // tableData: [{
      //   protocol: 'tcp',
      //   ip: '127.0.0.1',
      //   port: 22,
      //   state: 'OPEN'
      // },{
      //   protocol: 'tcp',
      //   ip: '127.0.0.1',
      //   port: 80,
      //   state: 'CLOSE'
      // },{
      //   protocol: 'udp',
      //   ip: '127.0.0.1',
      //   port: 53,
      //   state: 'FILTER'
      // }],

    }
  },
  // mounted:function() {
    // this.fetch();
  // },
  methods: {
    tableRowClassName({row, rowIndex}) {
      if (row.state === 'CLOSE') {
        return 'close-row';
      } else if (row.state === 'OPEN') {
        return 'open-row';
      } else if (row.state === 'FILTER') {
        return 'filter-row';
      }
      return '';
    },
    scan: async function() {
      console.log('submit!');

      var form_protocol = this.formInline.protocol;
      var form_ip = this.formInline.ip;
      var form_port = this.formInline.port;
      if (form_protocol === '') {
        alert("protocol is empty!");
        return;
      } else if (form_ip === '')  {
        alert("ip is empty!");
        return;
      } else if (form_port === '' && form_protocol !== 'icmp') {
        alert("port is empty!");
        return;
      }

      try {

        var rsp = await this.$http.post('/scan', {
          protocol: form_protocol,
          ip: form_ip,
          port: form_port,
        })
          for (var i=0; i < rsp.data.data.length; i++) {
            let row = rsp.data.data[i]
            if (row.state === 0) {
              row.state = 'CLOSE'
            } else if (row.state === 1) {
              row.state = 'OPEN'
            } else if (row.state === 2) {
              row.state = 'FILTER'
            } else {
              row.state = "UNKNOWN"
            }
            // icmp不显示端口
            if (form_protocol == "icmp") {
              row.port = null
            }
            console.log(row);
          }
          this.tableData = rsp.data.data
      }
      catch(err) {
        alert(err);
      }
    },
    clear() {
      console.log('clear!');
      this.tableData = [];
    }
  }
}
</script>



<style>
  .el-table .close-row {
    background: #FFCCCC;
  }

  .el-table .open-row {
    background: #CCFF99;

  }

  .el-table .filter-row {
    background: #CCCCCC;
  }
</style>
