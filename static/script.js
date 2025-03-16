const checkbox = document.getElementById('dark-mode-checkbox');
const darkModeLabel = document.getElementById('dark-mode-label');

// Function to set the theme
function setTheme(isDarkMode) {
    if (isDarkMode) {
        document.body.classList.add('dark-mode');
        darkModeLabel.textContent = 'Dark Mode';
    } else {
        document.body.classList.remove('dark-mode');
        darkModeLabel.textContent = 'Light Mode';
    }
    // Store the theme preference in local storage
    localStorage.setItem('dark-mode', isDarkMode);
}
// Check if there's a stored preference
const storedDarkMode = localStorage.getItem('dark-mode');

if (storedDarkMode === 'true') {
    checkbox.checked = true;
    setTheme(true);
} else {
    checkbox.checked = false;
    setTheme(false);
}

checkbox.addEventListener('change', () => {
    setTheme(checkbox.checked);
});