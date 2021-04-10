
var domains = []

function webSocketHandler(data) {
        var data = JSON.parse(data)

        $('#dataTable').DataTable().row.add(Object.values(data))
                .draw();


}


$(document).ready(function () {

        setTimeout(initServerVPNConfig(), 1000)


        $('#dataTable').DataTable({
                dom: 'Bfrtip',
                buttons: [
                        'copy', 'csv', 'excel', 'pdf', 'print'
                ],
                "order": [4, 'desc'],
                "processing": true,
                "stateSave": true,
                "deferRender": true,

                "columnDefs": [{
                        "targets": 0,

                        "createdCell": function (td, cellData, rowData, row, col) {
                                $(td).html('<a href=https://' + DOMPurify.sanitize(cellData) + '>' + DOMPurify.sanitize(cellData) + '</a>');



                                if (!domains.includes(cellData)) {
                                        domains.push(cellData)
                                }

                                document.getElementById("uniqueDomainsCounter").innerText = domains.length

                        }






                },

                {
                        "targets": 1,

                        "createdCell":
                                function (td, cellData, rowData, row, col) {
                                        if (cellData.split("***")[1]) {
                                            //    console.log(cellData.split("***"))
                                                var violation = $(td)[0].innerText.split("***")[0]
                                                var violationData = $(td)[0].innerText.split("***")[1]    
                                                var Myhtml = '<b>' + DOMPurify.sanitize(violation) + ': ' + '</b><span style="color:red;"><b>' + DOMPurify.sanitize(violationData) + '</b></span>'
                                                $(td).html(Myhtml)
                                        }



                                }

                },

                {
                        "targets": 4,

                        "createdCell":
                                function (td, cellData, rowData, row, col) {


                                        document.getElementById("ViolationCounter").innerText = cellData
                                }

                }


                ]






        });
        var socket = io({ transports: ['websocket'], upgrade: false });


        // We clear the table so if a client reconnects it doesn't duplicate entries 
        socket.on('connect', () => {
                var table = $('#dataTable').DataTable();
                table.clear()
                table.draw();


        });


        socket.on('ViolationResponse', function (data) {

                webSocketHandler(data)
        })




});





function getphorcysobject(id) {
        var domain = window.origin + "/api/v1/getphorchysobject?id=" + id

        var myRequest = new Request(domain);
        fetch(myRequest).then(function (response) {
                return response.text().then(function (text) {




                        let clean = DOMPurify.sanitize(text);
                        //var data = JSON.stringify(clean, null, '2')
                        $("#decoderObjectModal").modal('show')
                        var jsonObj = JSON.parse(clean)
                        //$("#decoderObject").html(jsonObj)

                        document.getElementById("decoderObject").textContent = JSON.stringify(jsonObj, null, 2);




                });
        });

}


// Should only have to do this once - to see if the you are not running in container or if you haven't generted server config.. This request will generate the server config and start the proxy
function initServerVPNConfig() {
        var domain = window.origin + "/initserverconfig"
        var myRequest = new Request(domain);
        fetch(myRequest).then(function (response) {
                return response.text().then(function (text) {
                        switch (text) {
                                case 'local':
                                        break;
                                case 'False':
                                        $("#vpnconfigmodal").modal('show')
                                        initServerVPNConfig()
                                        break;
                                case 'True':
                                        $('#initserverconfigDiv').hide()
                                        $('#configureDiv').show()
                                        break
                        }


                });
        });
}

function fetchRules() {
const container = document.getElementById('jsoneditor')
const options = {
    mode: 'code',
    modes: ['code'],
    mainMenuBar: false,
    statusBar: false,
    onError: function (err) {
      alert("Invlalid JSON")
    },
  }
var domain = window.origin + "/api/v1/myrule_settings"
fetch(domain)
   .then(response => response.json())
  .then(data =>




   editor = new JSONEditor(container, options, data)

);

    $('.modal-content').resizable({
      //alsoResize: ".modal-dialog",
      minHeight: 300,
      minWidth: 300
    });
    $('.modal-dialog').draggable();

    $('#myrulessettings').on('show.bs.modal', function() {
      $(this).find('.modal-body').css({
        'max-height': '100%'
      });
    });


        }





function cleareditor()
{
    document.getElementById("jsoneditor").innerHTML = "";
}




function checkIPFirst() {

        var ip = document.getElementById("ipinput").value;
        if (ValidateIPaddress(ip)) {
                setTimeout(checkVPNConfigFirst(ip), 10000)

        }

}

function checkVPNConfigFirst(ip = 'none') {

        var data = {'ip': ip}

        var domain = window.origin + "/api/v1/vpnconfigpoll"
        var myRequest = new Request(domain);
        fetch(myRequest, {
                method: 'post', headers: {'Content-Type': 'application/json'}, body:JSON.stringify(data)}).then(function (response) {
                return response.text().then(function (text) {
                        switch (text) {
                                case 'True':
                                        $('#configureDiv').hide()
                                        $('#stepOneStart').show()
                                        $('#closeModalButton').hide()
                                        $('#nextOnVPNInstructions').show()
                                        break;
                                case 'False':
                                        $('#generateButton').hide()
                                        $('#loadingButton').show()
                                        $("input").prop('disabled', true);
                                        $("#loadingButton").prop('disabled', true);
                                        checkVPNConfigFirst(ip = 'none')


                        }


                });
        });


}


function ValidateIPaddress(ipaddress) {
        if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ipaddress)) {
                return (true)
        }
        alert("You have entered an invalid IP address!")
        return (false)
}

function showinstallvpnmodal() {

// On click of the next button in the VPN config wizard on the VPN Config Page

        $('#nextOnVPNInstructions').hide()
$('#stepOneStart').hide()
$('#openVPNDIV').show()
$('#showMitmproxyInstructions').show()
$('#backOnVPNInstructions').show()
$('#backOnMitmproxyInstructions').hide()
$('#mitmproxyinstructions').hide()
}

function showmitmproxyinstructions() {

        // The next button once the Open VPN app install is done 
        $('#nextOnVPNInstructionst').hide()
        $('#openVPNDIV').hide()
        $('#mitmproxyinstructions').show()
        $('#backOnVPNInstructions').hide()
        $('#showMitmproxyInstructions').hide()
        $('#backOnMitmproxyInstructions').show()
        }

function goBacktoDownloadVPNConfigs() {

// On click to go back to the Download VPN Configs Page 
$('#nextOnVPNInstructions').show()
$('#openVPNDIV').hide()
$('#showMitmproxyInstructions').hide()
$('#stepOneStart').show()
$('#backOnVPNInstructions').hide()
$('#mitmproxyinstructions').hide()


}

function goBackToOpenVPNAppPage() {

        showinstallvpnmodal()


}