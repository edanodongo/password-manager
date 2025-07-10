document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.toggle-password').forEach(function(toggle) {
    toggle.addEventListener('click', function() {
      const input = this.previousElementSibling;
      if (input.type === 'password') {
        input.type = 'text';
        this.querySelector('i').classList.remove('fa-eye');
        this.querySelector('i').classList.add('fa-eye-slash');
      } else {
        input.type = 'password';
        this.querySelector('i').classList.remove('fa-eye-slash');
        this.querySelector('i').classList.add('fa-eye');
      }
    });
  });
});
