const Pi = window.Pi;

Pi.init({
    version: "2.0",
    sandbox: true
});

async function authenticateUser() {

    try {

        const scopes = ['username', 'payments'];

        const auth = await Pi.authenticate(
            scopes,
            onIncompletePaymentFound
        );

        console.log(auth);

    } catch (err) {

        console.error(err);
    }
}
if (window.Pi) {

    console.log("Pi Browser detected");

} else {

    alert("Please open in Pi Browser");
}

function onIncompletePaymentFound(payment) {

    console.log(payment);
}
