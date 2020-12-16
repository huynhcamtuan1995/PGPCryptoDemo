var vue = new Vue({
    el: '#app',
    data: {
        title: "PGP DEMO",
        name: "tuan",
        passphrase: "123456",
        publicKey: "",
        privateKey: "",
        type: 1
    },
    computed: {

    },
    methods: {
        copy2input: function (e) {
            var copyPublic = $('[name="publicKey"]').val();
            var copyPrivate = $('[name="privateKey"]').val();
            var copyPassphrase = $('[name="passphrase"]').val();
            $('[name="publicKey' + e.target.dataset.source + '"]').val(copyPublic);
            $('[name="privateKey' + e.target.dataset.source + '"]').val(copyPrivate);
            $('[name="passphrase' + e.target.dataset.source + '"]').val(copyPassphrase);
            toastr.success('Copied to clipboard.');
        },
        copy2clipboard: function (e) {
            var copyText = $('textarea[name="' + e.target.dataset.name + '"]');
            copyText[0].select();
            document.execCommand("copy");
            toastr.success('Copied to clipboard.');
        },
        generateKey: function (e) {
            e.preventDefault();
            var self = this;
            var name = $('input[name="name"]').val();
            var passphrase = $('input[name="passphrase"]').val();

            if (!name || !passphrase) {
                alert("name and passphrase cannot empty");
                return;
            }
            $.ajax({
                url: "/PGP/GeneradeKeyPair",
                type: "POST",
                data: {
                    name: name,
                    passphrase: passphrase
                },
                success: function (data, textStatus, jqXHR) {
                    self.name = data.name;
                    self.passphrase = data.pass;
                    self.publicKey = data.publicKey;
                    self.privateKey = data.privateKey;
                    toastr.success('Successed');
                },
                error: function (jqXHR, textStatus, errorThrown) {
                    toastr.error('Error');
                }
            })

        },
        encryptData: function (e) {
            e.preventDefault();
            var message = $('textarea[name="message1"]').val();
            var publicKey = $('textarea[name="publicKey1"]').val();
            var privateKey = $('textarea[name="privateKey1"]').val();
            var passphrase = $('input[name="passphrase1"]').val();
            var type = $('input[name="type"]').is(':checked') ? 1 : 0;

            $.ajax({
                url: "/PGP/EncryptPGP",
                type: "POST",
                data: {
                    message: message,
                    publicKey: publicKey,
                    privateKey: privateKey,
                    passphrase: passphrase,
                    type: type
                },
                success: function (data, textStatus, jqXHR) {
                    $('textarea[name="encryptResult"]').val(data);
                    toastr.success('Successed');
                },
                error: function (jqXHR, textStatus, errorThrown) {
                    toastr.error('Error');
                }
            })
        },

        decryptData: function (e) {
            e.preventDefault();
            var message = $('textarea[name="message2"]').val();
            var privateKey = $('textarea[name="privateKey2"]').val();
            var passphrase = $('input[name="passphrase2"]').val();

            $.ajax({
                url: "/PGP/DecryptPGP",
                type: "POST",
                data: {
                    encryptedMessage: message,
                    privateKey: privateKey,
                    passphrase: passphrase,
                },
                success: function (data, textStatus, jqXHR) {
                    $('textarea[name="decryptResult"]').val(data);
                    toastr.success('Successed');
                },
                error: function (jqXHR, textStatus, errorThrown) {
                    toastr.error('Error');
                }
            })
        }
    }
});