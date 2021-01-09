
function startTCP() {

  var data = {'vpn':'tcp'}
  var myRequest = new Request(window.origin + '/api/v1/startvpn');
  fetch(myRequest, {
    method: 'post', headers: {'Content-Type': 'application/json'}, body:JSON.stringify(data)})
    alert('TCP VPN Started!')
}

function startUDP() {

  var data = {'vpn':'udp'}
  var myRequest = new Request(window.origin + '/api/v1/startvpn');
  fetch(myRequest, {
    method: 'post', headers: {'Content-Type': 'application/json'}, body:JSON.stringify(data)})
    alert('UDP VPN Started!')
}

function stopVPN() {

  var data = {'stop':'vpn'}
  var myRequest = new Request(window.origin + '/api/v1/stopvpn');
  fetch(myRequest, {
    method: 'post', headers: {'Content-Type': 'application/json'}, body:JSON.stringify(data)})
    alert('VPN Shutdown')
}

function startProxy() {
  var data = {'start': 'True'}
  var myRequest = new Request(window.origin + '/api/v1/startproxy?start=True');
  fetch(myRequest, {
    method: 'post', headers: {'Content-Type': 'application/json'}, body:JSON.stringify(data)})
    alert('Proxy Started!')
}

function checkVPNConfig(ip = 'none') {

  var data = {'ip': ip}
  var domain = window.origin + "/api/v1/vpnconfigpoll"
  var myRequest = new Request(domain);
  fetch(myRequest, {
    method: 'post', headers: {'Content-Type': 'application/json'}, body:JSON.stringify(data)}).then(function (response) {
    return response.text().then(function (text) {
      switch (text) {
        case 'True':
          $('#VPNID').hide()
          $('#downloadVPNConfigs').show()
          $("#deleteConfigDiv").show()
          break;
        case 'False':
          $('#vpnconfigbutton').hide()
          $('#loadingButton2').show()
          $("input").prop('disabled', true);
          $("#loadingButton2").prop('disabled', true);
          checkVPNConfig(ip = 'none')
          


      }


    });
  });


}

function checkIP() {

  var ip = document.getElementById("ipinput2").value;
  if (ValidateIPaddress(ip)) {
    checkVPNConfig(ip)

  }

}

function ValidateIPaddress(ipaddress) {
  if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ipaddress)) {
    return (true)
  }
  alert("You have entered an invalid IP address!")
  return (false)
}

function checkIfClientConfigGenerated() {

  var domain = window.origin + "/checkIfClientConfigGenerated"
  var myRequest = new Request(domain);
  fetch(myRequest).then(function (response) {
    return response.text().then(function (text) {
      if (text == 'True') {
        $('#VPNID').hide()

      }
      else {
        $('#downloadVPNConfigs').hide()
        $('#VPNID').show()
        $('#vpnconfigbutton').hide()
        $('#loadingButton2').show()
        $("input").prop('disabled', true);
        $("#loadingButton").prop('disabled', true);
        setTimeout(checkVPNConfig(ip = 'none'), 1000)
     
     
     
      }



    });



  });


}

function deleteconfig() {

var data = {'delete': 'True'}
var myRequest = new Request(window.origin + '/api/v1/deletevpnconfig');
  fetch(myRequest, {
    method: 'post', headers: {'Content-Type': 'application/json'}, body:JSON.stringify(data)}).then(function(response) {
    return response.text().then(function(text) {
        
      $('#downloadVPNConfigs').hide()
      $('#VPNID').show()

      $('#vpnconfigbutton').show()
      $('#loadingButton2').hide()
      $("input").prop('disabled', false);
      $("#loadingButton2").prop('disabled', false);
      $("#deleteConfigDiv").hide()


        
    });
  });
}

//Check to see once the modal is loaded if we have Generated a Config 
function checkifgenerated() {

  var myRequest = new Request(window.origin + '/checkIfClientConfigGenerated');
  fetch(myRequest).then(function(response) {
    return response.text().then(function(text) {
        if (text == 'True') {
          
      $('#downloadVPNConfigs').show()
      $('#VPNID').hide()
      $("#deleteConfigDiv").show()
        }

        else if (text == 'False') {
          
          $("#downloadVPNConfigs").hide()
      $('#vpnconfigbutton').show()
      $('#loadingButton2').hide()
      $("input").prop('disabled', false);
      $("#loadingButton2").prop('disabled', false);

        }

        
    });
  });




}
