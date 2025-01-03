function validateForm(event) {
    // Validation logic
    const emailField = document.getElementById('email');
    const passwordField = document.getElementById('password');
    const emailWarning = document.getElementById('email-warning');
    const passwordWarning = document.getElementById('password-warning');

    let isValid = true;

    // Validate email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(emailField.value)) {
        emailWarning.style.display = 'block';
        isValid = false;
    } else {
        emailWarning.style.display = 'none';
    }

    // Validate password
    if (!(passwordField.value.length === 10 && /^\d+$/.test(passwordField.value))) {
        passwordWarning.style.display = 'block';
        isValid = false;
    } else {
        passwordWarning.style.display = 'none';
    }

    if (!isValid) {
        event.preventDefault();
    }
}
