document.addEventListener('DOMContentLoaded', () => {
  const pwdInput = document.getElementById('password-input');
  const toggleBtn = document.getElementById('toggle-password');
  const strengthBar = document.getElementById('strength-bar');
  const strengthText = document.getElementById('strength-text');

  const strengthNames = ['Very Weak','Weak','Medium','Strong','Very Strong'];
  const strengthColors = ['bg-red-500','bg-orange-500','bg-yellow-400','bg-green-400','bg-green-600'];

  function updateStrength() {
    const pwd = pwdInput.value;
    // simple scoring: length, uppercase, digit, special
    let score = 0;
    if (pwd.length >= 8) score++;
    if (/[A-Z]/.test(pwd)) score++;
    if (/\d/.test(pwd)) score++;
    if (/[^A-Za-z0-9]/.test(pwd)) score++;
    // cap at max 4
    score = Math.min(score, 4);

    // update bar and text
    strengthBar.value = score;
    // remove old color classes
    strengthColors.forEach(c => strengthBar.classList.remove(c));
    strengthBar.classList.add(strengthColors[score]);
    strengthText.textContent = strengthNames[score];
    strengthText.className = `mt-2 text-sm font-medium ${score < 2 ? 'text-red-600' : score < 3 ? 'text-yellow-600' : 'text-green-600'}`;
  }

  pwdInput.addEventListener('input', updateStrength);

  toggleBtn.addEventListener('click', () => {
    const type = pwdInput.type === 'password' ? 'text' : 'password';
    pwdInput.type = type;
    toggleBtn.textContent = type === 'password' ? 'Show' : 'Hide';
  });

  updateStrength();
});
