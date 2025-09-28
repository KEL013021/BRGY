<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>BRGY GO</title>
  <link href="../bootstrap5/css/bootstrap.min.css" rel="stylesheet"/>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">

  <!-- Select2 CSS -->
  <link href="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css" rel="stylesheet" />

  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
  <!-- Select2 JS -->
  <script src="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js"></script>
  <script src="../ajax/ph-address-selector.js"></script> <!-- yung script mo for PH address -->
  <link rel="stylesheet" href="../css/login.css"/>
</head>
<body>
    <!-- Sign Up -->
    <div class="container" id="container">
    <div class="form-container sign-up">
      <form id="signupForm" action="../database/signup.php" method="POST">
        <h2 class="header">Create Account</h2>
        
        <!-- STEP 1 -->
        <div class="step active w-100" id="step1">
          <input type="email" name="email" placeholder="Email" required />
          <div class="position-relative w-100">
            <input type="password" name="password" placeholder="Password" id="signupPassword" required>
            <i class="bi bi-eye-slash-fill fs-5" id="toggleSignupPassword"></i>
          </div>
          <small id="passwordStrength" class="text-danger d-block"></small>
          <div class="position-relative w-100">
            <input type="password" name="confirm_password" placeholder="Confirm Password" id="confirmPassword" required>
            <i class="bi bi-eye-slash-fill fs-5" id="toggleConfirmPassword"></i>
          </div>
          <small id="confirmError" class="text-danger d-block" style="min-height:18px;visibility:hidden;">Passwords do not match</small>

          <div class="d-flex justify-content-center w-100 mt-2">
            <button type="button" id="nextBtn">Next</button>
          </div>
        </div>

        <!-- STEP 2 -->
        <div class="step" id="step2" style="width: 325px;">
          <h4 class="mb-3 text-center">Address Information</h4>
          <select id="region" class="form-select mb-2" required>
            <option value="" disabled selected hidden>Select Region</option>
          </select>
          <input type="hidden" name="region" id="region-text">

          <select id="province" class="form-select mb-2" required>
            <option value="" disabled selected hidden>Select Province</option>
          </select>
          <input type="hidden" name="province" id="province-text">

          <select id="city" class="form-select mb-2" required>
            <option value="" disabled selected hidden>Select City</option>
          </select>
          <input type="hidden" name="city" id="city-text">

          <select id="barangay" class="form-select mb-1" required>
            <option value="" disabled selected hidden>Select Barangay</option>
          </select>
          <input type="hidden" name="barangay" id="barangay-text">

          <div class="d-flex align-items-center w-100 mb-1">
            <input class="form-check-input me-2" type="checkbox" id="terms" name="toa" required style="width:10px;"oninvalid="this.setCustomValidity('You must agree to the Terms and Conditions before continuing')" 
            oninput="this.setCustomValidity('')">
            <label class="form-check-label small text-muted mb-1" for="terms">
              I agree to the <a href="#" class="link-primary">Terms & Conditions</a>
            </label>
          </div>

          <div class="d-flex justify-content-between w-100 gap-3">
            <button type="button" id="prevBtn">Back</button>
            <button type="submit">Sign Up</button>
          </div>
        </div>
      </form>
    </div>

    <!-- Sign In -->
    <div class="form-container sign-in">
      <form action="../database/login.php" method="POST">
        <h2 class="header">Log In</h2>
        <input type="email" name="email" placeholder="Email" required />
        <div class="position-relative w-100">
          <input type="password" name="password" placeholder="Password" id="signinPassword" required>
          <i class="bi bi-eye-slash-fill fs-5" id="toggleSigninPassword"></i>
        </div>
        <a href="#">Forgot your password?</a>
        <button type="submit">Log In</button>
      </form>
    </div>

    <!-- Toggle Panels -->
    <div class="toggle-container">
      <div class="toggle">
        <div class="toggle-panel toggle-left" style="align-items: center;">
          <h2>Welcome Back!</h2>
          <p>To stay connected, please login with your info</p>
          <button class="hidden" id="login">Log In</button>
        </div>
        <div class="toggle-panel toggle-right" style="align-items: center;">
          <h2>Hello, Friend!</h2>
          <p>Enter your details and start your journey with us</p>
          <button class="hidden" id="register">Sign Up</button>
        </div>
      </div>
    </div>
  </div>

 <!-- Success Modal -->
<!-- ================= SUCCESS MODAL ================= -->
<div class="modal fade" id="signupSuccessModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content shadow rounded-4 border-0">
      <div class="modal-header border-0">
        <h5 class="modal-title text-success fw-bold">
          <i class="bi bi-check-circle-fill me-2"></i> Success
        </h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body text-center">
        <p class="mb-2">You have successfully signed up.</p>
        <p class="small text-muted mb-0">Please login to continue.</p>
      </div>
      <div class="modal-footer border-0 justify-content-center">
        <button class="btn" data-bs-dismiss="modal" aria-label="Close">Go to Login</button>
      </div>
    </div>
  </div>

</div>
<script src="../bootstrap5/js/bootstrap.bundle.min.js"></script>
<script>
  const container = document.getElementById("container");
  document.getElementById("register").addEventListener("click", () => container.classList.add("active"));
  document.getElementById("login").addEventListener("click", () => container.classList.remove("active"));

  /* Password toggle */
  function togglePassword(inputId, toggleId) {
    const input = document.getElementById(inputId);
    const toggle = document.getElementById(toggleId);
    toggle.addEventListener("click", () => {
      const type = input.type === "password" ? "text" : "password";
      input.type = type;
      toggle.classList.toggle("bi-eye");
      toggle.classList.toggle("bi-eye-slash-fill");
    });
  }
  togglePassword("signupPassword","toggleSignupPassword");
  togglePassword("confirmPassword","toggleConfirmPassword");
  togglePassword("signinPassword","toggleSigninPassword");

  /* Password strength + confirm */
  const signupPassword=document.getElementById("signupPassword");
  const confirmPassword=document.getElementById("confirmPassword");
  const passwordStrength=document.getElementById("passwordStrength");
  const confirmError=document.getElementById("confirmError");

  function checkPasswordStrength(password){
    signupPassword.classList.remove("is-valid","is-invalid","is-medium");
    if(password.length>8){
      passwordStrength.textContent="Strong password";passwordStrength.style.color="green";
      signupPassword.classList.add("is-valid");
    }else if(password.length>=6){
      passwordStrength.textContent="Medium strength";passwordStrength.style.color="orange";
      signupPassword.classList.add("is-medium");
    }else{
      passwordStrength.textContent="Weak password (min 6 characters)";passwordStrength.style.color="red";
      signupPassword.classList.add("is-invalid");
    }
  }
  function validateConfirmPassword(){
    if(confirmPassword.value===""){confirmPassword.classList.remove("is-valid","is-invalid");confirmError.style.visibility="hidden";return;}
    if(confirmPassword.value===signupPassword.value){
      confirmPassword.classList.remove("is-invalid");confirmPassword.classList.add("is-valid");confirmError.style.visibility="hidden";
    }else{
      confirmPassword.classList.remove("is-valid");confirmPassword.classList.add("is-invalid");confirmError.style.visibility="visible";
    }
  }
  signupPassword.addEventListener("input",()=>{checkPasswordStrength(signupPassword.value);validateConfirmPassword();});
  confirmPassword.addEventListener("input",validateConfirmPassword);

  /* Multi-step */
  const step1=document.getElementById("step1");
  const step2=document.getElementById("step2");
  document.getElementById("nextBtn").addEventListener("click",()=>{
    validateConfirmPassword();
    if(confirmPassword.classList.contains("is-invalid")) return;
    if(signupPassword.classList.contains("is-invalid")) return;
    step1.classList.remove("active");
    step2.classList.add("active");
  });
  document.getElementById("prevBtn").addEventListener("click",()=>{
    step2.classList.remove("active");
    step1.classList.add("active");
  });
</script>

<?php if (isset($_GET['success'])): ?>
<script>
  document.addEventListener("DOMContentLoaded", function() {
    var myModal = new bootstrap.Modal(document.getElementById('signupSuccessModal'));
    myModal.show();
  });
</script>
<?php endif; ?>

</body>
</html>
