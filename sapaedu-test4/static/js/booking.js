
/**
 * Meeting Room Booking JavaScript
 * Handles interactive elements and real-time updates
 */

document.addEventListener('DOMContentLoaded', function() {
    // Only initialize form features if elements exist
    if (document.querySelector('input[type="date"], input[type="time"]')) {
        initializeDateTimePickers();
    }
    if (document.querySelector('form')) {
        initializeFormValidation();
    }
    initializeTooltips();
    initializeTelegramWebApp();
});
/**
 * Initialize Telegram WebApp functionality
 */
function initializeTelegramWebApp() {
    console.log('Checking Telegram WebApp environment...');
    
    // Multiple detection attempts for better reliability
    function checkTelegramWebApp() {
        if (window?.Telegram?.WebApp) {
            console.log('Telegram WebApp detected');
            const tg = window.Telegram.WebApp;
            tg.ready();
            
            // Expand WebApp to full height
            tg.expand();
            
            // Get user data from Telegram
            const user = tg.initDataUnsafe?.user;
            console.log('Telegram user data:', user);
            
            if (user?.id) {   // ✅ заменено на optional chaining
                console.log('User ID found:', user.id);
                // Check if we're on telegram auth page and don't have telegram_id in URL
                if (window.location.pathname === '/telegram-auth' && !window.location.search.includes('telegram_id=')) {
                    console.log('Redirecting with Telegram ID...');
                    window.location.href = `/telegram-auth?telegram_id=${user.id}`;
                    return true;
                }
            } else {
                console.log('No user data available from Telegram WebApp');
            }
            
            // Set WebApp theme
            if (tg.colorScheme === 'dark') {
                document.body.classList.add('dark-theme');
            }
            
            return true;
        }
        return false;
    }
    
    // Try immediate detection
    if (checkTelegramWebApp()) {
        return;
    }
    
    // Try with delay for script loading
    setTimeout(function() {
        if (!checkTelegramWebApp()) {
            console.log('Not running in Telegram WebApp environment');
            // Show additional guidance for non-Telegram access only on auth page
            if (window.location.pathname === '/telegram-auth') {
                console.log('Showing Telegram access instructions');
                showTelegramInstructions();
            }
        }
    }, 500);
    
    // Final attempt with longer delay
    setTimeout(function() {
        checkTelegramWebApp();
    }, 1000);
}

/**
 * Show instructions for Telegram access
 */
function showTelegramInstructions() {
    const instructions = document.querySelector('.alert-info');
    if (instructions) {
        instructions.style.display = 'block';
    }
}

/**
 * Initialize date and time pickers using Flatpickr
 */
function initializeDateTimePickers() {
    // Date picker configuration
    const dateInputs = document.querySelectorAll('input[type="date"]');
    dateInputs.forEach(input => {
        if (window.flatpickr) {
            flatpickr(input, {
                minDate: "today",
                dateFormat: "Y-m-d",
                theme: "dark"
            });
        }
    });

    // Time picker configuration
    const timeInputs = document.querySelectorAll('input[type="time"]');
    timeInputs.forEach(input => {
        if (window.flatpickr) {
            flatpickr(input, {
                enableTime: true,
                noCalendar: true,
                dateFormat: "H:i",
                time_24hr: true,
                minuteIncrement: 15,
                theme: "dark"
            });
        }
    });
}

/**
 * Initialize form validation
 */
function initializeFormValidation() {
    const forms = document.querySelectorAll('form');

    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!validateForm(this)) {
                e.preventDefault();
                e.stopPropagation();
            }

            this.classList.add('was-validated');
        });

        // Real-time validation
        const inputs = form.querySelectorAll('input, textarea, select');
        inputs.forEach(input => {
            input.addEventListener('blur', function() {
                validateField(this);
            });

            input.addEventListener('input', function() {
                if (this.classList.contains('is-invalid')) {
                    validateField(this);
                }
            });
        });

        // Initialize booking form specific validation
        initializeBookingFormValidation(form);
    });
}

/**
 * Initialize booking form specific validation
 */
function initializeBookingFormValidation(form) {
    const startTimeInput = form.querySelector('input[name="start_time"]');
    const endTimeInput = form.querySelector('input[name="end_time"]');
    
    if (!startTimeInput || !endTimeInput) {
        return; // Not a booking form
    }
    
    let userSetEndTime = false;

    // Detect if user manually sets end time
    endTimeInput.addEventListener('change', function() {
        userSetEndTime = true;
    });

    // Auto-fill end time when start time is selected
    startTimeInput.addEventListener('change', function() {
        if (!userSetEndTime && this.value) {
            const startTime = new Date(`2000-01-01T${this.value}`);
            let endTime = new Date(startTime.getTime() + 60 * 60 * 1000); // Add 1 hour

            // Check if end time exceeds 18:00, if so set to 18:00
            const maxEndTime = new Date(`2000-01-01T18:00`);
            if (endTime > maxEndTime) {
                endTime = maxEndTime;
            }

            const endTimeString = endTime.toTimeString().slice(0, 5);
            endTimeInput.value = endTimeString;
        }
        validateWorkingHours(startTimeInput, endTimeInput);
        validateDateTime(startTimeInput, endTimeInput);
    });

    function validateWorkingHours(startInput, endInput) {
        if (startInput.value && endInput.value) {
            const startTime = new Date(`2000-01-01T${startInput.value}`);
            const endTime = new Date(`2000-01-01T${endInput.value}`);
            const earliestTime = new Date(`2000-01-01T08:00`);
            const latestTime = new Date(`2000-01-01T18:00`);

            if (startTime < earliestTime || endTime > latestTime) {
                showFieldError(startInput, 'Start time must be between 08:00 and 18:00');
                showFieldError(endInput, 'End time must be between 08:00 and 18:00');
            }
        }
    }

    function validateDateTime(startInput, endInput) {
        if (startInput.value && endInput.value) {
            if (startInput.value >= endInput.value) {
                showFieldError(endInput, 'End time must be after start time');
            }
        }
    }
}
/**
 * Validate entire form
 */
function validateForm(form) {
    let isValid = true;
    const inputs = form.querySelectorAll('input[required], textarea[required], select[required]');

    inputs.forEach(input => {
        if (!validateField(input)) {
            isValid = false;
        }
    });

    // Special validation for time range
    const startTime = form.querySelector('input[name="start_time"]');
    const endTime = form.querySelector('input[name="end_time"]');

    if (startTime?.value && endTime?.value) {   // ✅ optional chaining
        if (startTime.value >= endTime.value) {
            showFieldError(endTime, 'End time must be after start time');
            isValid = false;
        }
    }

    // Validate date is not in the past
    const dateInput = form.querySelector('input[name="date"]');
    if (dateInput?.value) {   // ✅ optional chaining
        const selectedDate = new Date(dateInput.value);
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        if (selectedDate < today) {
            showFieldError(dateInput, 'Cannot select past dates');
            isValid = false;
        }
    }

    return isValid;
}

/**
 * Validate individual field
 */
function validateField(field) {
    const value = field.value.trim();
    let isValid = true;

    // Clear previous validation state
    field.classList.remove('is-valid', 'is-invalid');
    clearFieldError(field);

    // Required field validation
    if (field.hasAttribute('required') && !value) {
        showFieldError(field, 'This field is required');
        isValid = false;
    }

    // Email validation
    if (field.type === 'email' && value) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(value)) {
            showFieldError(field, 'Please enter a valid email address');
            isValid = false;
        }
    }

    // Name validation (minimum 2 characters)
    if (field.name === 'user_name' && value && value.length < 2) {
        showFieldError(field, 'Name must be at least 2 characters long');
        isValid = false;
    }

    if (isValid) {
        field.classList.add('is-valid');
    }

    return isValid;
}

/**
 * Show field error
 */
function showFieldError(field, message) {
    field.classList.add('is-invalid');

    let errorDiv = field.parentNode.querySelector('.invalid-feedback');
    if (!errorDiv) {
        errorDiv = document.createElement('div');
        errorDiv.className = 'invalid-feedback';
        field.parentNode.appendChild(errorDiv);
    }

    errorDiv.textContent = message;
}

/**
 * Clear field error
 */
function clearFieldError(field) {
    const errorDiv = field.parentNode.querySelector('.invalid-feedback');
    if (errorDiv) {
        errorDiv.remove();
    }
}

/**
 * Initialize Bootstrap tooltips
 */
function initializeTooltips() {
    if (typeof bootstrap !== 'undefined') {
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
}

/**
 * Utility function to format time
 */
function formatTime(timeString) {
    const time = new Date(`1970-01-01T${timeString}`);
    return time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

/**
 * Utility function to format date
 */
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString([], { 
        weekday: 'short', 
        year: 'numeric', 
        month: 'short', 
        day: 'numeric' 
    });
}

/**
 * Show loading state
 */
function showLoading(element, message = 'Loading...') {
    element.innerHTML = `
        <div class="text-center text-muted">
            <i class="fas fa-spinner fa-spin me-2"></i>
            ${message}
        </div>
    `;
}

/**
 * Show error state
 */
function showError(element, message = 'An error occurred') {
    element.innerHTML = `
        <div class="text-center text-danger">
            <i class="fas fa-exclamation-triangle me-2"></i>
            ${message}
        </div>
    `;
}

/**
 * Auto-dismiss alerts after 5 seconds
 */
document.addEventListener('DOMContentLoaded', function() {
    const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    alerts.forEach(alert => {
        if (typeof bootstrap !== 'undefined' && bootstrap.Alert) {
            setTimeout(() => {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }, 5000);
        }
    });
});
