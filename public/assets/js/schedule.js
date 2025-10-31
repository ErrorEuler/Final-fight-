document.addEventListener('DOMContentLoaded', () => {
    const generateBtn = document.getElementById('generate-schedules-btn');
    generateBtn.addEventListener('click', () => {
        document.getElementById('generate-form').submit();
    });
});

document.addEventListener('DOMContentLoaded', () => {
    const curriculumSelect = document.getElementById('generate_curriculum_id');
    if (curriculumSelect.value) {
        updateYearLevels();
    }
    curriculumSelect.onchange = updateYearLevels; // Ensure it triggers on change
});