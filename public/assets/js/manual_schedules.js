let currentEditingId = null;
let currentSemesterCourses = {};
let validationTimeout;
let currentDeleteScheduleId = null;
const DEBOUNCE_DELAY = 300;

// Enhanced Drag and Drop with Conflict Detection
let draggedElement = null;
let originalPosition = null;

function handleDragStart(e) {
    draggedElement = e.target.closest(".schedule-card");
    if (!draggedElement) return;
    
    // Store original position for revert if needed
    originalPosition = {
        day: draggedElement.closest('.drop-zone').dataset.day,
        startTime: draggedElement.closest('.drop-zone').dataset.startTime,
        endTime: draggedElement.closest('.drop-zone').dataset.endTime,
        element: draggedElement
    };
    
    e.dataTransfer.setData("text/plain", draggedElement.dataset.scheduleId);
    e.dataTransfer.effectAllowed = "move";
    draggedElement.classList.add("dragging", "opacity-50");
    
    console.log("🚀 Drag started:", {
        scheduleId: draggedElement.dataset.scheduleId,
        originalPosition: originalPosition
    });
}

function handleDragEnd(e) {
    if (draggedElement) {
        draggedElement.classList.remove("dragging", "opacity-50");
    }
    draggedElement = null;
    originalPosition = null;
    
    document.querySelectorAll(".drop-zone.drag-over").forEach((zone) => {
        zone.classList.remove("drag-over");
    });
    
    document.querySelectorAll(".drop-zone.conflict").forEach((zone) => {
        zone.classList.remove("conflict");
    });
    
    console.log("🏁 Drag ended");
}

function handleDragEnter(e) {
    const dropZone = e.target.closest(".drop-zone");
    if (dropZone && draggedElement) {
        dropZone.classList.add("drag-over");
        
        // Check for conflicts in real-time
        checkDropZoneConflicts(dropZone);
        
        e.preventDefault();
    }
}

function handleDragOver(e) {
    if (e.target.classList.contains("drop-zone")) {
        e.preventDefault();
        e.dataTransfer.dropEffect = "move";
    }
}

function handleDragLeave(e) {
    if (e.target.classList.contains("drop-zone")) {
        e.target.classList.remove("drag-over");
        e.target.classList.remove("conflict");
    }
}

async function handleDrop(e) {
  e.preventDefault();
  const dropZone = e.target.closest(".drop-zone");

  if (!dropZone || !draggedElement) {
    console.log("❌ Invalid drop zone or no dragged element");
    return;
  }

  dropZone.classList.remove("drag-over", "conflict");

  const scheduleId = e.dataTransfer.getData("text/plain");
  const newDay = dropZone.dataset.day;
  const newStartTime = dropZone.dataset.startTime;
  const newEndTime = dropZone.dataset.endTime;

  console.log("🎯 Drop detected:", {
    scheduleId,
    newDay,
    newStartTime,
    newEndTime,
  });

  // Check for conflicts using your PHP function
  const conflicts = await checkScheduleConflicts(
    scheduleId,
    newDay,
    newStartTime,
    newEndTime
  );

  if (conflicts.length > 0) {
    console.warn("❌ Conflicts detected:", conflicts);
    showDropConflicts(conflicts);
    revertDrag();
    return;
  }

  // If no conflicts, proceed with the move
  performScheduleMove(scheduleId, newDay, newStartTime, newEndTime, dropZone);
}

function checkScheduleConflicts(scheduleId, newDay, newStartTime, newEndTime) {
  return new Promise((resolve) => {
    const currentSchedule = window.scheduleData.find(
      (s) => s.schedule_id == scheduleId
    );

    if (!currentSchedule) {
      resolve([]);
      return;
    }

    // Prepare data for PHP conflict check
    const formData = new URLSearchParams({
      action: "check_drag_conflicts",
      schedule_id: scheduleId,
      section_id: currentSchedule.section_id,
      faculty_id: currentSchedule.faculty_id,
      room_id: currentSchedule.room_id || "",
      day_of_week: newDay,
      start_time: newStartTime + ":00",
      end_time: newEndTime + ":00",
      semester_id: window.currentSemester?.semester_id || "",
    });

    fetch("/chair/generate-schedules", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: formData,
    })
      .then((response) => response.json())
      .then((result) => {
        if (result.success && result.conflicts) {
          resolve(result.conflicts);
        } else {
          resolve([]);
        }
      })
      .catch((error) => {
        console.error("Conflict check error:", error);
        resolve([]); // Allow drop if check fails
      });
  });
}

// Get conflict type for better messaging
function getConflictType(newStart, newEnd, existingStart, existingEnd) {
    if (newStart >= existingStart && newEnd <= existingEnd) return 'completely_overlaps';
    if (newStart < existingStart && newEnd > existingEnd) return 'completely_contains';
    if (newStart < existingEnd && newEnd > existingEnd) return 'overlaps_end';
    if (newStart < existingStart && newEnd > existingStart) return 'overlaps_start';
    return 'partial_overlap';
}

function showDropZoneConflictTooltip(dropZone, conflicts) {
  removeConflictTooltip(dropZone);

  const tooltip = document.createElement("div");
  tooltip.className =
    "conflict-tooltip absolute bottom-full left-0 rounded p-2 text-xs z-50 whitespace-nowrap max-w-xs";

  // Group conflicts by severity
  const highConflicts = conflicts.filter((c) => c.severity === "high");
  const mediumConflicts = conflicts.filter((c) => c.severity === "medium");
  const lowConflicts = conflicts.filter((c) => c.severity === "low");

  let tooltipContent =
    '<div class="font-semibold mb-1">⚠️ Scheduling Conflicts:</div>';

  // Show high severity conflicts first
  if (highConflicts.length > 0) {
    tooltipContent += '<div class="text-red-700 font-semibold">Critical:</div>';
    highConflicts.slice(0, 2).forEach((conflict) => {
      tooltipContent += `<div class="ml-2 text-red-600">• ${conflict.message}</div>`;
    });
  }

  // Medium severity
  if (mediumConflicts.length > 0) {
    tooltipContent +=
      '<div class="text-orange-600 font-medium mt-1">Important:</div>';
    mediumConflicts.slice(0, 2).forEach((conflict) => {
      tooltipContent += `<div class="ml-2 text-orange-600">• ${conflict.message}</div>`;
    });
  }

  // Low severity
  if (lowConflicts.length > 0) {
    tooltipContent += '<div class="text-yellow-600 mt-1">Note:</div>';
    lowConflicts.slice(0, 1).forEach((conflict) => {
      tooltipContent += `<div class="ml-2 text-yellow-600">• ${conflict.message}</div>`;
    });
  }

  // Show total count if there are more conflicts
  const totalShown =
    highConflicts.slice(0, 2).length +
    mediumConflicts.slice(0, 2).length +
    lowConflicts.slice(0, 1).length;
  const totalConflicts = conflicts.length;

  if (totalConflicts > totalShown) {
    tooltipContent += `<div class="mt-1 text-gray-500">+ ${
      totalConflicts - totalShown
    } more conflicts</div>`;
  }

  tooltip.innerHTML = tooltipContent;

  // Set background based on highest severity
  if (highConflicts.length > 0) {
    tooltip.classList.add("bg-red-100", "border-red-300", "text-red-800");
    dropZone.classList.add("conflict-high");
  } else if (mediumConflicts.length > 0) {
    tooltip.classList.add(
      "bg-orange-100",
      "border-orange-300",
      "text-orange-800"
    );
    dropZone.classList.add("conflict-medium");
  } else {
    tooltip.classList.add(
      "bg-yellow-100",
      "border-yellow-300",
      "text-yellow-800"
    );
    dropZone.classList.add("conflict-low");
  }

  tooltip.classList.add("border");
  dropZone.appendChild(tooltip);
}

function removeConflictTooltip(dropZone) {
    const existingTooltip = dropZone.querySelector('.conflict-tooltip');
    if (existingTooltip) {
        existingTooltip.remove();
    }
}

// Show drop conflicts to user
function showDropConflicts(conflicts) {
    const conflictMessages = conflicts.map(c => c.message).join('\n• ');
    showNotification(
        `Cannot move schedule due to conflicts:\n• ${conflictMessages}`,
        'error',
        8000
    );
}

// Revert drag to original position
function revertDrag() {
    if (originalPosition && originalPosition.element) {
        originalPosition.element.classList.remove('opacity-50');
        showNotification("Schedule reverted due to conflicts", "warning", 3000);
    }
}

// Perform the actual schedule move
function performScheduleMove(scheduleId, newDay, newStartTime, newEndTime, dropZone) {
    const scheduleIndex = window.scheduleData.findIndex(s => s.schedule_id == scheduleId);
    
    if (scheduleIndex === -1) {
        console.error("Schedule not found:", scheduleId);
        showNotification("Error: Schedule not found", "error");
        return;
    }

    const originalSchedule = window.scheduleData[scheduleIndex];
    
    // Calculate new end time based on original duration
    const originalStart = new Date(`2000-01-01 ${originalSchedule.start_time.substring(0, 5)}`);
    const originalEnd = new Date(`2000-01-01 ${originalSchedule.end_time.substring(0, 5)}`);
    const durationMs = originalEnd - originalStart;
    const newEnd = new Date(`2000-01-01 ${newStartTime}`);
    newEnd.setMinutes(newEnd.getMinutes() + (durationMs / 60000));
    const formattedEndTime = newEnd.toTimeString().substring(0, 5);

    console.log("🔄 Moving schedule:", {
        from: `${originalSchedule.day_of_week} ${originalSchedule.start_time}-${originalSchedule.end_time}`,
        to: `${newDay} ${newStartTime}-${formattedEndTime}`,
        duration: `${durationMs / 60000} minutes`
    });

    // Update schedule data
    window.scheduleData[scheduleIndex].day_of_week = newDay;
    window.scheduleData[scheduleIndex].start_time = newStartTime + ":00";
    window.scheduleData[scheduleIndex].end_time = formattedEndTime + ":00";

    // Update display
    safeUpdateScheduleDisplay(window.scheduleData);
    
    // Save to server
    saveScheduleMoveToServer(scheduleId, newDay, newStartTime, formattedEndTime);
    
    showNotification(`Schedule moved to ${newDay} ${newStartTime}-${formattedEndTime}`, "success");
}

// Save schedule move to server
function saveScheduleMoveToServer(scheduleId, newDay, newStartTime, newEndTime) {
    const formData = new URLSearchParams({
        action: 'update_schedule_drag',
        schedule_id: scheduleId,
        day_of_week: newDay,
        start_time: newStartTime + ":00",
        end_time: newEndTime + ":00"
    });

    fetch("/chair/generate-schedules", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: formData
    })
    .then(response => response.json())
    .then(result => {
        if (!result.success) {
            console.error("Failed to save schedule move:", result.message);
            showNotification("Warning: Schedule move not saved to server", "warning");
        } else {
            console.log("✅ Schedule move saved to server");
        }
    })
    .catch(error => {
        console.error("Error saving schedule move:", error);
        showNotification("Error: Failed to save schedule move", "error");
    });
}

async function checkDropZoneConflicts(dropZone) {
  if (!draggedElement) return;

  const scheduleId = draggedElement.dataset.scheduleId;
  const newDay = dropZone.dataset.day;
  const newStartTime = dropZone.dataset.startTime;
  const newEndTime = dropZone.dataset.endTime;

  const conflicts = await checkScheduleConflicts(
    scheduleId,
    newDay,
    newStartTime,
    newEndTime
  );

  if (conflicts.length > 0) {
    dropZone.classList.add("conflict");
    showDropZoneConflictTooltip(dropZone, conflicts);
  } else {
    dropZone.classList.remove("conflict");
    removeConflictTooltip(dropZone);
  }
}

// Initialize enhanced drag and drop
function initializeDragAndDrop() {
    const dropZones = document.querySelectorAll(".drop-zone");
    const draggables = document.querySelectorAll(".schedule-card.draggable");

    console.log("🔄 Initializing drag and drop:", {
        dropZones: dropZones.length,
        draggables: draggables.length
    });

    // Remove existing event listeners
    dropZones.forEach((zone) => {
        zone.removeEventListener("dragover", handleDragOver);
        zone.removeEventListener("dragenter", handleDragEnter);
        zone.removeEventListener("dragleave", handleDragLeave);
        zone.removeEventListener("drop", handleDrop);
    });

    draggables.forEach((draggable) => {
        draggable.removeEventListener("dragstart", handleDragStart);
        draggable.removeEventListener("dragend", handleDragEnd);
    });

    // Add new event listeners
    dropZones.forEach((zone) => {
        zone.addEventListener("dragover", handleDragOver);
        zone.addEventListener("dragenter", handleDragEnter);
        zone.addEventListener("dragleave", handleDragLeave);
        zone.addEventListener("drop", handleDrop);
    });

    draggables.forEach((draggable) => {
        draggable.addEventListener("dragstart", handleDragStart);
        draggable.addEventListener("dragend", handleDragEnd);
    });
}

function validateFieldRealTime(fieldType, value, relatedFields = {}) {
  clearTimeout(validationTimeout);
  validationTimeout = setTimeout(() => {
    const formData = new FormData(document.getElementById("schedule-form"));
    const partialData = {
      action: "validate_partial",
      semester_id: window.currentSemester?.semester_id,
      [fieldType]: value,
      ...relatedFields,
      course_code: formData.get("course_code")?.trim() || "",
      section_name: formData.get("section_name")?.trim() || "",
      faculty_name: formData.get("faculty_name")?.trim() || "",
      room_name: formData.get("room_name")?.trim() || "Online",
      day_of_week: formData.get("day_of_week") || "",
      start_time: formData.get("start-time") || "",
      end_time: formData.get("end-time") || ""
    };
    console.log(`Validating ${fieldType}:`, partialData);

    fetch("/chair/generate-schedules", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(partialData)
    })
      .then(response => response.json())
      .then(result => {
        console.log("Validation response:", result);

        // Clear previous warnings for this field type
        const fieldId = fieldType.replace("_", "-");
        removeConflictWarning(fieldId);

        if (result.success && result.conflicts?.length > 0) {
          result.conflicts.forEach(conflict => {
            let fieldId, message, warningLevel = 'error';

            switch (true) {
              case conflict.includes("Section"):
                fieldId = "section-name";
                message = conflict.includes("schedule") ?
                  `👥 ${conflict}` :
                  "👥 This section has scheduling conflicts. Please check the section's existing schedules.";
                break;
              case conflict.includes("Faculty"):
                fieldId = "faculty-name";
                message = conflict.includes("schedule") ?
                  `👨‍🏫 ${conflict}` :
                  "👨‍🏫 Faculty member has overlapping schedules. Consider adjusting time or day.";
                warningLevel = 'error';
                break;
              case conflict.includes("Room"):
                fieldId = "room-name";
                message = conflict.includes("schedule") ?
                  `🏫 ${conflict}` :
                  "🏫 Room is already occupied during this time. Please select another room or time slot.";
                warningLevel = 'error';
                break;
              case conflict.includes("time"):
                fieldId = "start-time";
                const endFieldId = "end-time";
                const timeMessage = conflict.includes("schedule") ?
                  `⏰ ${conflict}` :
                  "⏰ Time conflict detected. This time slot overlaps with existing schedules.";

                displayConflictWarning(fieldId, timeMessage, 'error');
                displayConflictWarning(endFieldId, timeMessage, 'error');
                break;
              default:
                fieldId = fieldType.replace("_", "-");
                message = result.message || "⚠️ Validation issue detected. Please check your input.";
                warningLevel = 'warning';
            }

            if (fieldId && !conflict.includes("time")) {
              displayConflictWarning(fieldId, message, warningLevel);
            }
          });
        } else if (!result.success && result.message) {
          displayConflictWarning(fieldType.replace("_", "-"),
            `⚠️ ${result.message}`,
            'warning'
          );
        } else {
          // No conflicts - show success message for important fields
          const fieldId = fieldType.replace("_", "-");
          if (['faculty-name', 'room-name', 'section-name'].includes(fieldId) && value) {
            displayConflictWarning(fieldId,
              "✅ No conflicts detected for this selection.",
              'success'
            );
          }
        }
      })
      .catch(error => {
        console.error("Real-time validation error:", error);
        const fieldId = fieldType.replace("_", "-");
        displayConflictWarning(fieldId,
          "🔧 Validation service temporarily unavailable. Please check your inputs manually.",
          'warning'
        );
      });
  }, DEBOUNCE_DELAY);
}

function calculateEndTime(startTime, durationMinutes = 60) {
  const [hours, minutes] = startTime.split(":").map(Number);
  const startDate = new Date(2000, 0, 1, hours, minutes);
  const endDate = new Date(startDate.getTime() + durationMinutes * 60000);
  return endDate.toTimeString().substring(0, 5);
}

function handleDrop(e) {
  e.preventDefault();
  const dropZone = e.target.closest(".drop-zone");
  if (!dropZone || !draggedElement) return;
  dropZone.classList.remove("drag-over");
  const scheduleId = e.dataTransfer.getData("text/plain");
  const newDay = dropZone.dataset.day;
  const newStartTime = dropZone.dataset.startTime;
  const newEndTime = dropZone.dataset.endTime;
  console.log("Dropping schedule:", scheduleId, "to", newDay, newStartTime, newEndTime);

  const scheduleIndex = window.scheduleData.findIndex(
    (s) => s.schedule_id == scheduleId
  );
  if (scheduleIndex !== -1) {
    const originalSchedule = window.scheduleData[scheduleIndex];
    const originalStart = new Date(`2000-01-01 ${originalSchedule.start_time.substring(0, 5)}`);
    const originalEnd = new Date(`2000-01-01 ${originalSchedule.end_time.substring(0, 5)}`);
    const durationMinutes = (originalEnd - originalStart) / (1000 * 60);
    const formattedEndTime = calculateEndTime(newStartTime, durationMinutes);

    console.log("Time update details:", {
      originalDuration: durationMinutes + " minutes",
      newStart: newStartTime,
      newEnd: formattedEndTime,
    });

    window.scheduleData[scheduleIndex].day_of_week = newDay;
    window.scheduleData[scheduleIndex].start_time = newStartTime + ":00";
    window.scheduleData[scheduleIndex].end_time = formattedEndTime + ":00";

    safeUpdateScheduleDisplay(window.scheduleData);
    showNotification(`Schedule moved to ${newDay} ${newStartTime}-${formattedEndTime}`, "success");
  }
}

function initializeDragAndDrop() {
  const dropZones = document.querySelectorAll(".drop-zone");
  const draggables = document.querySelectorAll(".draggable");
  console.log("Initializing drag and drop:", {
    dropZones: dropZones.length,
    draggables: draggables.length,
  });

  dropZones.forEach((zone) => {
    zone.removeEventListener("dragover", handleDragOver);
    zone.removeEventListener("dragenter", handleDragEnter);
    zone.removeEventListener("dragleave", handleDragLeave);
    zone.removeEventListener("drop", handleDrop);

    zone.addEventListener("dragover", handleDragOver);
    zone.addEventListener("dragenter", handleDragEnter);
    zone.addEventListener("dragleave", handleDragLeave);
    zone.addEventListener("drop", handleDrop);
  });

  draggables.forEach((draggable) => {
    draggable.removeEventListener("dragstart", handleDragStart);
    draggable.removeEventListener("dragend", handleDragEnd);

    draggable.addEventListener("dragstart", handleDragStart);
    draggable.addEventListener("dragend", handleDragEnd);
  });
}

// Open delete ALL schedules modal
function deleteAllSchedules() {
  console.log("Opening delete all schedules modal...");
  const modal = document.getElementById("delete-confirmation-modal");
  if (modal) {
    modal.classList.remove("hidden");
    modal.classList.add("flex");
    console.log("Delete all modal opened successfully");
  } else {
    console.error("Delete confirmation modal element not found!");
    if (confirm("Are you sure you want to delete all schedules? This action cannot be undone.")) {
      confirmDeleteAllSchedules();
    }
  }
}

// Close delete all modal
function closeDeleteModal() {
  console.log("Closing delete all modal...");
  const modal = document.getElementById("delete-confirmation-modal");
  if (modal) {
    modal.classList.add("hidden");
    modal.classList.remove("flex");
  }
}

function confirmDeleteAllSchedules() {
  console.log("Confirming deletion of all schedules...");

  // Show loading overlay
  const loadingOverlay = document.getElementById("loading-overlay");
  if (loadingOverlay) {
    loadingOverlay.classList.remove("hidden");
    const loadingText = loadingOverlay.querySelector("p");
    if (loadingText) {
      loadingText.textContent = "Deleting schedules...";
    }
  }

  // Close modal immediately
  closeDeleteModal();

  // FIX: Send 'true' as string, backend expects this
  fetch("/chair/generate-schedules", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      action: "delete_schedules",
      confirm: "true", // Changed from "1" to "true"
    }),
  })
    .then((response) => {
      console.log("Delete all response status:", response.status);
      if (!response.ok)
        throw new Error(`HTTP error! status: ${response.status}`);
      return response.text(); // Get text first to see raw response
    })
    .then((text) => {
      console.log("Delete all raw response:", text);
      let data;
      try {
        data = JSON.parse(text);
      } catch (e) {
        console.error("Failed to parse JSON:", e);
        throw new Error("Invalid JSON response: " + text.substring(0, 200));
      }

      console.log("Delete all response data:", data);

      // Hide loading
      if (loadingOverlay) {
        loadingOverlay.classList.add("hidden");
        const loadingText = loadingOverlay.querySelector("p");
        if (loadingText) {
          loadingText.textContent = "Generating schedules...";
        }
      }

      if (data.success) {
        const deletedCount = data.deleted_count || 0;
        showNotification(
          `Successfully deleted ${deletedCount} schedule(s)!`,
          "success"
        );

        // Clear schedule data
        window.scheduleData = [];

        // Update displays
        safeUpdateScheduleDisplay([]);

        // Rebuild course mappings
        buildCurrentSemesterCourseMappings();

        // Remove completion banner if exists
        const banner = document.getElementById("schedule-completion-banner");
        if (banner) {
          banner.remove();
        }

        // Hide generation results
        const generationResults = document.getElementById("generation-results");
        if (generationResults) {
          generationResults.classList.add("hidden");
        }

        // Reload after short delay
        setTimeout(() => {
          location.reload();
        }, 1500);
      } else {
        showNotification(
          "Error: " +
            (data.message || "Failed to delete all schedules") +
            (data.debug ? "\n\nDebug: " + JSON.stringify(data.debug) : ""),
          "error"
        );
      }
    })
    .catch((error) => {
      // Hide loading on error
      if (loadingOverlay) {
        loadingOverlay.classList.add("hidden");
        const loadingText = loadingOverlay.querySelector("p");
        if (loadingText) {
          loadingText.textContent = "Generating schedules...";
        }
      }

      console.error("Delete all error:", error);
      showNotification(
        "Error deleting all schedules: " + error.message,
        "error"
      );
    });
}

// Open single delete modal
function openDeleteSingleModal(scheduleId, courseCode, sectionName, day, startTime, endTime) {
    
    // Check if we're getting the event object instead of scheduleId
    if (scheduleId && typeof scheduleId === 'object' && scheduleId.target) {
        return;
    }
    
    // Store the original values for debugging
    window._deleteDebug = {
        originalScheduleId: scheduleId,
        originalType: typeof scheduleId
    };
    
    // More robust validation
    let finalScheduleId = scheduleId;
    
    // Check for common null/undefined cases
    if (finalScheduleId == null || finalScheduleId === 'null' || finalScheduleId === 'undefined' || finalScheduleId === '') {
        console.warn("⚠️ Invalid scheduleId detected, attempting recovery...");
        
        // Try to get from the event (if available)
        if (window.event) {
            const element = window.event.target.closest('button');
            if (element) {
                const onclick = element.getAttribute('onclick');
                console.log("Button onclick attribute:", onclick);
            }
        }
        
        // Try to find by course and section as last resort
        if (courseCode && sectionName) {
            const matchingSchedule = window.scheduleData.find(s => 
                s.course_code === courseCode && s.section_name === sectionName
            );
            if (matchingSchedule && matchingSchedule.schedule_id) {
                finalScheduleId = matchingSchedule.schedule_id;
                console.log("✅ Recovered scheduleId from data:", finalScheduleId);
            }
        }
    }
    
    // Final validation
    if (!finalScheduleId || finalScheduleId === 'null' || finalScheduleId === 'undefined') {
        showNotification("Error: Could not identify schedule. Please refresh and try again.", "error");
        return;
    }
    
    console.log("✅ Final scheduleId for deletion:", finalScheduleId, "type:", typeof finalScheduleId);
    currentDeleteScheduleId = finalScheduleId;

    // Update modal
    const detailsElement = document.getElementById("single-delete-details");
    if (detailsElement) {
        detailsElement.innerHTML = `
            <div class="text-sm">
                <div class="font-semibold">${escapeHtml(courseCode)} - ${escapeHtml(sectionName)}</div>
                <div class="text-gray-600 mt-1">${escapeHtml(day)} • ${escapeHtml(startTime)} to ${escapeHtml(endTime)}</div>
                <div class="text-xs text-gray-500 mt-2">Schedule ID: ${finalScheduleId}</div>
            </div>
        `;
    }

    const modal = document.getElementById("delete-single-modal");
    if (modal) {
        modal.classList.remove("hidden");
        modal.classList.add("flex");
    }
    
    console.log("🔍 OPEN DELETE MODAL - END");
}

// Enhanced confirmDeleteSingleSchedule with detailed logging
function confirmDeleteSingleSchedule() {
    if (!currentDeleteScheduleId || currentDeleteScheduleId === 'null' || currentDeleteScheduleId === 'undefined') {
        console.error("❌ currentDeleteScheduleId is invalid:", currentDeleteScheduleId);
        showNotification("Error: No schedule selected for deletion.", "error");
        return;
    }

    // Convert to number to ensure it's not a string
    const scheduleIdToDelete = parseInt(currentDeleteScheduleId);
    if (isNaN(scheduleIdToDelete) || scheduleIdToDelete <= 0) {
        console.error("❌ Invalid scheduleId after conversion:", scheduleIdToDelete);
        showNotification("Error: Invalid schedule ID format.", "error");
        return;
    }

    console.log("✅ Sending delete request for scheduleId:", scheduleIdToDelete);

    // Show loading
    const loadingOverlay = document.getElementById("loading-overlay");
    if (loadingOverlay) {
        loadingOverlay.classList.remove("hidden");
        loadingOverlay.querySelector("p").textContent = "Deleting schedule...";
    }

    closeDeleteSingleModal();

    // Create form data with proper validation
    const formData = new URLSearchParams();
    formData.append('action', 'delete_schedule');
    formData.append('schedule_id', scheduleIdToDelete.toString());
    formData.append('confirm', 'true');

    console.log("📤 Sending POST data:", {
        action: 'delete_schedule',
        schedule_id: scheduleIdToDelete,
        confirm: 'true'
    });

    fetch("/chair/generate-schedules", {
        method: "POST",
        headers: { 
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest"
        },
        body: formData
    })
    .then((response) => {
        console.log("📥 Response status:", response.status);
        return response.text();
    })
    .then((text) => {
        console.log("📥 Raw response:", text);
        let data;
        try {
            data = JSON.parse(text);
        } catch (e) {
            console.error("❌ JSON parse error:", e);
            throw new Error("Invalid JSON: " + text.substring(0, 200));
        }
        return data;
    })
    .then((data) => {
        console.log("📥 Parsed response:", data);
        
        if (loadingOverlay) loadingOverlay.classList.add("hidden");

        if (data.success) {
            showNotification("Schedule deleted successfully!", "success");
            
            // Update UI
            window.scheduleData = window.scheduleData.filter(
                s => s.schedule_id != scheduleIdToDelete
            );
            safeUpdateScheduleDisplay(window.scheduleData);
            setTimeout(initializeDragAndDrop, 100);
            buildCurrentSemesterCourseMappings();
        } else {
            showNotification(data.message || "Failed to delete schedule", "error");
        }
    })
    .catch((error) => {
        console.error("❌ Fetch error:", error);
        if (loadingOverlay) loadingOverlay.classList.add("hidden");
        showNotification("Error: " + error.message, "error");
    })
    .finally(() => {
        currentDeleteScheduleId = null;
        console.log("🔍 CONFIRM DELETE - END");
    });
}

// Close single delete modal
function closeDeleteSingleModal() {
  console.log("Closing single delete modal...");
  const modal = document.getElementById("delete-single-modal");
  if (modal) {
    modal.classList.add("hidden");
    modal.classList.remove("flex");
  }
  currentDeleteScheduleId = null;
}

// Helper function to delete schedule (calls openDeleteSingleModal)
function deleteSchedule(scheduleId) {
  const schedule = window.scheduleData.find((s) => s.schedule_id == scheduleId);
  if (schedule) {
    openDeleteSingleModal(
      scheduleId,
      schedule.course_code,
      schedule.section_name,
      schedule.day_of_week,
      formatTime(schedule.start_time.substring(0, 5)),
      formatTime(schedule.end_time.substring(0, 5))
    );
  } else {
    console.error("Schedule not found for deletion:", scheduleId);
    showNotification("Error: Schedule not found", "error");
  }
}

// Helper function for escaping HTML (if not already defined)
function escapeHtml(unsafe) {
  if (!unsafe) return "";
  return String(unsafe)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Close modals on ESC key
document.addEventListener("keydown", function (event) {
  if (event.key === "Escape") {
    closeDeleteModal();
    closeDeleteSingleModal();
    closeModal(); // Your existing modal close function
  }
});

// Close modals when clicking outside
document.addEventListener("click", function (event) {
  const deleteAllModal = document.getElementById("delete-confirmation-modal");
  const deleteSingleModal = document.getElementById("delete-single-modal");
  
  if (deleteAllModal && event.target === deleteAllModal) {
    closeDeleteModal();
  }
  
  if (deleteSingleModal && event.target === deleteSingleModal) {
    closeDeleteSingleModal();
  }
});

function formatTime(timeString) {
  if (!timeString) return "";
  const [hours, minutes] = timeString.split(":");
  const date = new Date(2000, 0, 1, hours, minutes);
  return date.toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    hour12: true,
  });
}

function showNotification(message, type = "success", duration = 5000) {
  const existingNotification = document.getElementById("notification");
  if (existingNotification) existingNotification.remove();

  const notificationDiv = document.createElement("div");
  notificationDiv.id = "notification";

  let notificationClass = "fixed top-4 right-4 z-50 max-w-sm w-full ";
  let iconClass = "";
  let textClass = "";
  let buttonClass = "";

  if (type === "success") {
    notificationClass += "bg-green-50 border border-green-200";
    iconClass = "fa-check-circle text-green-400";
    textClass = "text-green-800";
    buttonClass = "text-green-400 hover:text-green-600";
  } else if (type === "error") {
    notificationClass += "bg-red-50 border border-red-200";
    iconClass = "fa-exclamation-circle text-red-400";
    textClass = "text-red-800";
    buttonClass = "text-red-400 hover:text-red-600";
  } else {
    notificationClass += "bg-yellow-50 border border-yellow-200";
    iconClass = "fa-exclamation-triangle text-yellow-400";
    textClass = "text-yellow-800";
    buttonClass = "text-yellow-400 hover:text-yellow-600";
  }

  notificationClass += " rounded-lg shadow-lg transform transition-transform duration-300 translate-x-full";
  notificationDiv.className = notificationClass;

  notificationDiv.innerHTML =
    '<div class="flex p-4">' +
    '<div class="flex-shrink-0">' +
    '<i class="fas ' + iconClass + ' text-lg"></i>' +
    '</div>' +
    '<div class="ml-3 flex-1">' +
    '<p class="text-sm font-medium ' + textClass + ' whitespace-pre-line">' + message + '</p>' +
    '</div>' +
    '<div class="ml-auto pl-3">' +
    '<button class="inline-flex ' + buttonClass + '" onclick="this.parentElement.parentElement.parentElement.remove()">' +
    '<i class="fas fa-times"></i>' +
    '</button>' +
    '</div>' +
    '</div>';

  document.body.appendChild(notificationDiv);

  setTimeout(() => {
    notificationDiv.classList.remove("translate-x-full");
    notificationDiv.classList.add("translate-x-0");
  }, 100);

  setTimeout(() => {
    if (notificationDiv.parentElement) {
      notificationDiv.classList.add("translate-x-full");
      setTimeout(() => {
        if (notificationDiv.parentElement) notificationDiv.remove();
      }, 300);
    }
  }, duration);
}

// Enhanced autoFillCourseName with better messaging
function autoFillCourseName(courseCode) {
  const courseNameInput = document.getElementById("course-name");
  if (!courseCode || !courseNameInput) return;

  const enteredCode = courseCode.trim().toUpperCase();
  console.log("Looking up course:", enteredCode);

  // Clear previous warnings
  removeConflictWarning("course-code");
  removeConflictWarning("course-name");

  // Check for conflicts
  const conflict = validateCourseConflict(enteredCode, '');

  if (currentSemesterCourses[enteredCode]) {
    const course = currentSemesterCourses[enteredCode];
    courseNameInput.value = course.name;
    console.log("Found course:", course);

    // Show success message for valid course
    if (!conflict) {
      displayConflictWarning("course-code",
        "✅ Course found in curriculum! Course name auto-filled.",
        'success'
      );
    }

    setTimeout(() => {
      filterSectionsByYearLevel();
      handleSectionChange();
    }, 100);
  } else {
    console.log("Course not found in current semester");
    courseNameInput.value = "";
    resetSectionFilter();

    if (!conflict && enteredCode) {
      displayConflictWarning("course-code",
        "🔍 Course not found in current semester curriculum. Please verify the course code.",
        'warning'
      );
    }
  }
}

function filterSectionsByYearLevel() {
  const sectionSelect = document.getElementById("section-name");
  const courseCodeInput = document.getElementById("course-code");
  if (!sectionSelect || !courseCodeInput) return;

  const courseCode = courseCodeInput.value.trim().toUpperCase();
  if (!courseCode) {
    resetSectionFilter();
    return;
  }

  const course = currentSemesterCourses[courseCode];
  if (!course || !course.year_level) {
    resetSectionFilter();
    highlightConflictField("course-code", "No year level information found for course " + courseCode + ". Showing all sections.");
    return;
  }

  const targetYearLevel = course.year_level;
  console.log("Filtering sections for year level:", targetYearLevel, "from course:", courseCode);

  const allOptions = sectionSelect.querySelectorAll("option");
  allOptions.forEach((option) => option.style.display = "");

  const searchYear = targetYearLevel.toLowerCase().replace(" year", "").trim();
  let foundMatchingSections = false;

  const optgroups = sectionSelect.querySelectorAll("optgroup");
  optgroups.forEach((optgroup) => {
    const groupLabel = optgroup.label.toLowerCase();
    const groupYearLevel = groupLabel.replace(" year", "").trim();

    if (groupYearLevel === searchYear) {
      const options = optgroup.querySelectorAll("option");
      options.forEach((option) => option.style.display = "");
      optgroup.style.display = "";
      foundMatchingSections = true;
    } else {
      const options = optgroup.querySelectorAll("option");
      options.forEach((option) => option.style.display = "none");
      optgroup.style.display = "none";
    }
  });

  const selectedOption = sectionSelect.options[sectionSelect.selectedIndex];
  if (selectedOption && selectedOption.style.display === "none") {
    sectionSelect.value = "";
  }

  if (foundMatchingSections) {
    resetConflictStyles();
  } else {
    console.warn("No sections found for year level:", targetYearLevel);
    highlightConflictField("section-name", "No " + targetYearLevel + " sections found for " + courseCode + ". Please check section availability.");
    resetSectionFilter();
  }
}

function resetSectionFilter() {
  const sectionSelect = document.getElementById("section-name");
  if (!sectionSelect) return;

  const allOptions = sectionSelect.querySelectorAll("option");
  allOptions.forEach((option) => option.style.display = "");

  const optgroups = sectionSelect.querySelectorAll("optgroup");
  optgroups.forEach((optgroup) => optgroup.style.display = "");
}

function updateTimeFields() {
  const startTimeSelect = document.getElementById("start-time");
  const endTimeSelect = document.getElementById("end-time");
  const modalStartTime = document.getElementById("modal-start-time");
  const modalEndTime = document.getElementById("modal-end-time");

  if (startTimeSelect && modalStartTime) modalStartTime.value = startTimeSelect.value + ":00";
  if (endTimeSelect && modalEndTime) modalEndTime.value = endTimeSelect.value + ":00";
}

function updateDayField() {
  const daySelect = document.getElementById("day-select");
  const modalDay = document.getElementById("modal-day");
  if (daySelect && modalDay) modalDay.value = daySelect.value;
}

function handleScheduleSubmit(e) {
  e.preventDefault();
  console.log("Submitting schedule form...");
  resetConflictStyles();

  const currentSemesterId = window.currentSemester?.semester_id;
  if (!currentSemesterId) {
    showNotification("No active semester selected", "error");
    return;
  }

  const formData = new FormData(document.getElementById("schedule-form"));
  const data = {
    action: currentEditingId ? "update_schedule" : "add_schedule",
    schedule_id: formData.get("schedule_id"),
    course_code: formData.get("course_code").trim(),
    course_name: formData.get("course_name").trim(),
    section_name: formData.get("section_name").trim(),
    faculty_name: formData.get("faculty_name").trim(),
    room_name: formData.get("room_name").trim() || "Online",
    day_of_week: formData.get("day_of_week"),
    start_time: formData.get("start_time"),
    end_time: formData.get("end_time"),
    schedule_type: formData.get("schedule_type") || "f2f",
    semester_id: currentSemesterId,
  };
  console.log("Form data:", data);

  // Check for course conflicts
  const courseConflict = validateCourseConflict(data.course_code, data.course_name, currentEditingId);
  if (courseConflict) {
    highlightConflictField("course-code", courseConflict.message);
    highlightConflictField("course-name", courseConflict.message);
  }


  const validatePromises = [
    validateFieldRealTime("section_name", data.section_name),
    validateFieldRealTime("faculty_name", data.faculty_name, {
      day_of_week: data.day_of_week,
      start_time: data.start_time,
      end_time: data.end_time,
    }),
    validateFieldRealTime("room_name", data.room_name, {
      day_of_week: data.day_of_week,
      start_time: data.start_time,
      end_time: data.end_time,
    }),
    validateFieldRealTime("day_of_week", data.day_of_week, {
      faculty_name: data.faculty_name,
      room_name: data.room_name,
      start_time: data.start_time,
      end_time: data.end_time,
    }),
    validateFieldRealTime("start_time", data.start_time, {
      day_of_week: data.day_of_week,
      faculty_name: data.faculty_name,
      room_name: data.room_name,
    }),
    validateFieldRealTime("end_time", data.end_time, {
      day_of_week: data.day_of_week,
      start_time: data.start_time,
      faculty_name: data.faculty_name,
      room_name: data.room_name,
    }),
  ];

  Promise.all(validatePromises).then(() => {
    let hasConflicts = document.querySelectorAll(".border-red-500").length > 0;
    if (hasConflicts) {
      showNotification("Please resolve the highlighted conflicts before submitting.", "error");
      return;
    }

    let hasEmptyFields = false;
    const requiredFields = [
      { id: "course-code", value: data.course_code, name: "Course Code" },
      { id: "course-name", value: data.course_name, name: "Course Name" },
      { id: "section-name", value: data.section_name, name: "Section" },
      { id: "faculty-name", value: data.faculty_name, name: "Faculty" },
      { id: "day-select", value: data.day_of_week, name: "Day Pattern" },
    ];

    requiredFields.forEach((field) => {
      if (!field.value) {
        highlightConflictField(field.id, field.name + " is required");
        hasEmptyFields = true;
      }
    });

    if (hasEmptyFields) {
      showNotification("Please fill out all required fields.", "error");
      return;
    }

    if (data.start_time >= data.end_time) {
      highlightConflictField("start-time", "Start time must be before end time");
      highlightConflictField("end-time", "End time must be after start time");
      showNotification("End time must be after start time.", "error");
      return;
    }

    const submitButton = e.target.querySelector('button[type="submit"]');
    const originalText = submitButton.innerHTML;
    submitButton.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Saving...';
    submitButton.disabled = true;

    fetch("/chair/generate-schedules", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(data),
    })
      .then(response => response.json())
      .then(result => {
        console.log("Save response:", result);
        if (result.success) {
          closeModal();
          resetConflictStyles();
          let message = result.message || (currentEditingId ? "Schedule updated successfully!" : "Schedule added successfully!");

          if (result.schedules && result.schedules.length > 1) {
            message = "Schedules added successfully for " + result.schedules.length + " days!";
            result.schedules.forEach((schedule) => {
              window.scheduleData.push({ ...schedule, semester_id: currentSemesterId });
            });
          } else if (result.schedules && result.schedules.length === 1) {
            if (currentEditingId) {
              const index = window.scheduleData.findIndex((s) => s.schedule_id == currentEditingId);
              if (index !== -1) window.scheduleData[index] = { ...window.scheduleData[index], ...result.schedules[0], semester_id: currentSemesterId };
            } else {
              window.scheduleData.push({ ...result.schedules[0], semester_id: currentSemesterId });
            }
          }

          if (result.partial_success) message += " (" + result.failed_days + " day(s) had conflicts)";
          showNotification(message, "success");
          safeUpdateScheduleDisplay(window.scheduleData);
          initializeDragAndDrop();
          buildCurrentSemesterCourseMappings();
        } else {
          resetConflictStyles();
          if (result.conflicts && result.conflicts.length > 0) {
            result.conflicts.forEach(conflict => {
              if (conflict.includes("faculty")) highlightConflictField("faculty-name", conflict);
              if (conflict.includes("room")) highlightConflictField("room-name", conflict);
              if (conflict.includes("section")) highlightConflictField("section-name", conflict);
              if (conflict.includes("time")) {
                highlightConflictField("start-time", conflict);
                highlightConflictField("end-time", conflict);
              }
            });
            showNotification("Schedule conflicts detected:\n• " + result.conflicts.join("\n• "), "error", 10000);
          } else {
            showNotification(result.message || "Failed to save schedule.", "error");
          }
        }
      })
      .catch(error => {
        console.error("Error saving schedule:", error);
        showNotification("Error saving schedule: " + error.message, "error");
        resetConflictStyles();
      })
      .finally(() => {
        submitButton.innerHTML = originalText;
        submitButton.disabled = false;
      });
  });
}

function highlightConflictField(fieldId, message) {
  const field = document.getElementById(fieldId);
  if (field) {
    field.classList.add("border-red-500", "bg-red-50");
    field.classList.remove("border-gray-300", "bg-white");

    let tooltip = field.parentNode.querySelector(".conflict-tooltip");
    if (!tooltip) {
      tooltip = document.createElement("div");
      tooltip.className = "conflict-tooltip text-red-600 text-xs mt-1";
      field.parentNode.appendChild(tooltip);
    }
    tooltip.textContent = message;
  }
}

// Enhanced reset function
function resetConflictStyles() {
  const form = document.getElementById("schedule-form");
  if (!form) return;

  const fields = form.querySelectorAll("input, select, textarea");
  fields.forEach((field) => {
    const fieldId = field.id;
    removeConflictWarning(fieldId);
  });
}

function buildCurrentSemesterCourseMappings() {
  currentSemesterCourses = {};
  console.log("Building course mappings for current semester:", window.currentSemester);
  console.log("Available curriculum courses:", window.curriculumCourses);

  if (window.curriculumCourses && window.curriculumCourses.length > 0) {
    console.log("Using curriculum courses:", window.curriculumCourses.length);
    window.curriculumCourses.forEach((course) => {
      if (course.course_code && course.course_name) {
        currentSemesterCourses[course.course_code.trim().toUpperCase()] = {
          code: course.course_code,
          name: course.course_name,
          course_id: course.course_id,
          year_level: course.curriculum_year,
          semester: course.curriculum_semester,
          units: course.units,
          lecture_hours: course.lecture_hours,
          lab_hours: course.lab_hours,
        };
      }
    });

    console.log("Course mappings built:", Object.keys(currentSemesterCourses).length, "unique courses");
    console.log("Sample courses:", Object.values(currentSemesterCourses).slice(0, 3));
    updateCourseCodesDatalist();
  } else {
    console.warn("No curriculum courses found! Check if curriculum is set up correctly.");
    const currentSemesterId = window.currentSemester?.semester_id;
    if (currentSemesterId) {
      const currentSemesterSchedules = window.scheduleData.filter((schedule) => schedule.semester_id == currentSemesterId);
      console.log("Fallback: Using", currentSemesterSchedules.length, "schedules for current semester");

      currentSemesterSchedules.forEach((schedule) => {
        if (schedule.course_code && schedule.course_name) {
          currentSemesterCourses[schedule.course_code.trim().toUpperCase()] = {
            code: schedule.course_code,
            name: schedule.course_name,
            course_id: schedule.course_id,
          };
        }
      });
      updateCourseCodesDatalist();
    }
  }
}

function updateCourseCodesDatalist() {
  const courseCodesDatalist = document.getElementById("course-codes");
  if (!courseCodesDatalist) return;

  courseCodesDatalist.innerHTML = "";
  Object.values(currentSemesterCourses).forEach((course) => {
    const option = document.createElement("option");
    option.value = course.code;
    option.setAttribute("data-name", course.name);
    option.setAttribute("data-year-level", course.year_level || "");
    option.setAttribute("data-course-id", course.course_id || "");
    courseCodesDatalist.appendChild(option);
  });

  console.log("Updated course codes datalist with", courseCodesDatalist.children.length, "options");
}

// Enhanced syncCourseName with conflict detection
function syncCourseName() {
  const courseCodeInput = document.getElementById("course-code");
  const courseNameInput = document.getElementById("course-name");
  if (!courseCodeInput || !courseNameInput) return;

  const enteredCode = courseCodeInput.value.trim().toUpperCase();
  const enteredName = courseNameInput.value.trim();

  console.log("Looking up course:", enteredCode);

  // Check for conflicts
  const conflict = validateCourseConflict(enteredCode, enteredName);
  if (conflict) {
    highlightConflictField("course-code", conflict.message);
    if (enteredName) {
      highlightConflictField("course-name", conflict.message);
    }
  } else {
    resetConflictField("course-code");
    resetConflictField("course-name");
  }

  if (currentSemesterCourses[enteredCode]) {
    const course = currentSemesterCourses[enteredCode];
    courseNameInput.value = course.name;
    console.log("Found course:", course);
  } else {
    console.log("Course not found in current semester");
  }
}

// Enhanced syncCourseCode with conflict detection
function syncCourseCode() {
  const courseCodeInput = document.getElementById("course-code");
  const courseNameInput = document.getElementById("course-name");
  if (!courseCodeInput || !courseNameInput) return;

  const enteredName = courseNameInput.value.trim().toLowerCase();
  const matchingCourse = Object.values(currentSemesterCourses).find(
    (course) => course.name.toLowerCase() === enteredName
  );

  if (matchingCourse) {
    courseCodeInput.value = matchingCourse.code;
    console.log("Found matching course code:", matchingCourse.code);

    // Check for conflicts after syncing
    const conflict = validateCourseConflict(matchingCourse.code, enteredName);
    if (conflict) {
      highlightConflictField("course-code", conflict.message);
      highlightConflictField("course-name", conflict.message);
    } else {
      resetConflictField("course-code");
      resetConflictField("course-name");
    }
  }
}

// Enhanced section change handler with better messages
function handleSectionChange() {
  const sectionSelect = document.getElementById("section-name");
  const courseCodeInput = document.getElementById("course-code");
  const roomSelect = document.getElementById("room-name");
  if (!sectionSelect) return;

  const selectedSection = sectionSelect.value;
  const selectedOption = sectionSelect.options[sectionSelect.selectedIndex];
  console.log("Section changed to:", selectedSection);

  // Clear previous section warnings
  removeConflictWarning("section-name");

  if (selectedOption && roomSelect) {
    const sectionCapacity = extractCapacityFromSection(selectedOption.text);
    if (sectionCapacity) {
      highlightSuitableRooms(sectionCapacity);
      displayConflictWarning("room-name",
        `📊 Room highlighting adjusted for section capacity: ${sectionCapacity} students`,
        'info'
      );
    }
  }

  if (courseCodeInput && courseCodeInput.value) {
    validateCourseSectionCompatibility(courseCodeInput.value, selectedSection);
  }

  if (selectedSection) {
    checkExistingSectionSchedules(selectedSection);
  }

  updateSectionDetails(selectedOption);
}

function extractCapacityFromSection(sectionText) {
  const match = sectionText.match(/\((\d+)\/(\d+)\)/);
  return match ? parseInt(match[2]) : null;
}

function highlightSuitableRooms(requiredCapacity) {
  const roomSelect = document.getElementById("room-name");
  if (!roomSelect) return;

  const options = roomSelect.querySelectorAll("option");
  options.forEach((option) => {
    if (option.value === "Online") {
      option.style.backgroundColor = "#f0f9ff";
      return;
    }

    const roomCapacity = extractRoomCapacity(option.text);
    if (roomCapacity && roomCapacity >= requiredCapacity) {
      option.style.backgroundColor = "#f0fff4";
      option.title = "Capacity: " + roomCapacity + " (Meets requirement: " + requiredCapacity + ")";
    } else if (roomCapacity) {
      option.style.backgroundColor = "#fff0f0";
      option.title = "Capacity: " + roomCapacity + " (Required: " + requiredCapacity + ")";
    } else {
      option.style.backgroundColor = "";
      option.title = "";
    }
  });

  console.log("Highlighted rooms for capacity requirement:", requiredCapacity);
}

function extractRoomCapacity(roomText) {
  const match = roomText.match(/\((\d+)\)/);
  return match ? parseInt(match[1]) : null;
}

// Enhanced section compatibility check
function validateCourseSectionCompatibility(courseCode, sectionName) {
  const course = currentSemesterCourses[courseCode.toUpperCase()];
  if (!course || !course.year_level) return;

  const sectionSelect = document.getElementById("section-name");
  const selectedOption = sectionSelect.options[sectionSelect.selectedIndex];
  if (!selectedOption) return;

  const sectionYearLevel = selectedOption.getAttribute("data-year-level");
  if (sectionYearLevel && course.year_level !== sectionYearLevel) {
    console.warn("Course-Section Mismatch: Course (" + course.year_level + ") ≠ Section (" + sectionYearLevel + ")");
    displayConflictWarning("section-name",
      `📚 Year level mismatch: Course "${courseCode}" is for ${course.year_level} but section "${sectionName}" is ${sectionYearLevel}. This may not be appropriate.`,
      'warning'
    );
  } else {
    console.log("Course-section compatibility: OK");
    removeConflictWarning("section-name");
  }
}

// Enhanced existing section schedule check
function checkExistingSectionSchedules(sectionName) {
  const currentSemesterId = window.currentSemester?.semester_id;
  if (!currentSemesterId) return;

  const existingSchedules = window.scheduleData.filter(
    (schedule) => schedule.section_name === sectionName && schedule.semester_id == currentSemesterId
  );

  if (existingSchedules.length > 0) {
    console.log("Section " + sectionName + " has " + existingSchedules.length + " existing schedules:", existingSchedules);
    const scheduleCount = existingSchedules.length;
    const courseCodes = [...new Set(existingSchedules.map((s) => s.course_code))].join(", ");

    displayConflictWarning("section-name",
      `📅 Section "${sectionName}" already has ${scheduleCount} scheduled course(s): ${courseCodes}. Adding more schedules may affect student workload.`,
      'info'
    );
  } else {
    removeConflictWarning("section-name");
  }
}

function updateSectionDetails(selectedOption) {
  let detailsDiv = document.getElementById("section-details");
  if (!detailsDiv) {
    detailsDiv = document.createElement("div");
    detailsDiv.id = "section-details";
    detailsDiv.className = "mt-2 p-2 bg-gray-50 rounded text-sm";
    const sectionSelect = document.getElementById("section-name");
    sectionSelect.parentNode.appendChild(detailsDiv);
  }

  if (selectedOption && selectedOption.value) {
    const sectionText = selectedOption.text;
    const yearLevel = selectedOption.getAttribute("data-year-level");
    detailsDiv.innerHTML =
      '<div class="flex justify-between items-center">' +
      '<span class="font-medium">Section Details:</span>' +
      '<span class="text-blue-600">' + (yearLevel || "Unknown Year") + '</span>' +
      '</div>' +
      '<div class="text-gray-600 mt-1">' + sectionText + '</div>';
    detailsDiv.style.display = "block";
  } else {
    detailsDiv.style.display = "none";
  }
}

function openAddModal() {
  console.log("Opening add modal for current semester:", window.currentSemester);
  
  buildCurrentSemesterCourseMappings();

  const form = document.getElementById("schedule-form");
  if (form) form.reset();

  // Reset conflict styles specifically for course fields
  resetConflictField("course-code");
  resetConflictField("course-name");

   document.getElementById("start-time").value = "";
   document.getElementById("end-time").innerHTML =
     '<option value="">Select End Time</option>';
  document.getElementById("modal-title").textContent = "Add Schedule";
  document.getElementById("schedule-id").value = "";
  document.getElementById("modal-day").value = "Monday";
  document.getElementById("modal-start-time").value = "07:30";
  document.getElementById("modal-end-time").value = "08:30";
  document.getElementById("course-code").value = "";
  document.getElementById("course-name").value = "";
  document.getElementById("faculty-name").value = "";
  document.getElementById("room-name").value = "Online";
  document.getElementById("section-name").value = "";

  document.getElementById("day-select").value = "Monday";
  document.getElementById("start-time").value = "07:30";
  document.getElementById("end-time").value = "08:30";
  document.getElementById("schedule-type").value = "f2f";

  resetSectionFilter();

  const sectionDetails = document.getElementById("section-details");
  if (sectionDetails) sectionDetails.style.display = "none";

  currentEditingId = null;
  showModal();
}

function openAddModalForSlot(day, startTime, endTime) {
  console.log("Opening add modal for slot:", day, startTime, endTime);
  openAddModal();

  document.getElementById("modal-day").value = day;
  document.getElementById("modal-start-time").value = startTime;
  document.getElementById("modal-end-time").value = endTime;

  document.getElementById("day-select").value = day;
  document.getElementById("start-time").value = startTime;
  document.getElementById("end-time").value = endTime;
}

function editSchedule(scheduleId) {
  console.log("Editing schedule:", scheduleId);
  const schedule = window.scheduleData.find((s) => s.schedule_id == scheduleId);
  if (!schedule) {
    console.error("Schedule not found:", scheduleId);
    showNotification("Schedule not found", "error");
    return;
  }

  // Reset conflict styles when editing
  resetConflictField("course-code");
  resetConflictField("course-name");

  console.log("Found schedule:", schedule);

  if (schedule.semester_id != window.currentSemester?.semester_id) {
    showNotification("Can only edit schedules from current semester", "error");
    return;
  }

  buildCurrentSemesterCourseMappings();
  document.getElementById("modal-title").textContent = "Edit Schedule";
  document.getElementById("schedule-id").value = schedule.schedule_id;
  document.getElementById("course-code").value = schedule.course_code || "";
  document.getElementById("course-name").value = schedule.course_name || "";
  document.getElementById("faculty-name").value = schedule.faculty_name || "";
  document.getElementById("room-name").value = schedule.room_name || "";
  document.getElementById("section-name").value = schedule.section_name || "";

  const day = schedule.day_of_week || "Monday";
  document.getElementById("modal-day").value = day;
  document.getElementById("day-select").value = day;

  const startTime = schedule.start_time ? schedule.start_time.substring(0, 5) : "07:30";
  const endTime = schedule.end_time ? schedule.end_time.substring(0, 5) : "08:30";
  document.getElementById("modal-start-time").value = startTime;
  document.getElementById("modal-end-time").value = endTime;
  document.getElementById("start-time").value = startTime;
  document.getElementById("end-time").value = endTime;

  currentEditingId = scheduleId;
  showModal();
}

function showModal() {
  const modal = document.getElementById("schedule-modal");
  if (modal) {
    modal.classList.remove("hidden");
    modal.classList.add("flex");
    console.log("Modal shown");
  } else {
    console.error("Modal element not found!");
  }
}

function closeModal() {
  const modal = document.getElementById("schedule-modal");
  if (modal) {
    modal.classList.add("hidden");
    modal.classList.remove("flex");
  }
  const form = document.getElementById("schedule-form");
  if (form) form.reset();
  currentEditingId = null;
}

function saveAllChanges() {
  const currentSemesterId = window.currentSemester?.semester_id;
  const currentSemesterSchedules = window.scheduleData.filter((s) => s.semester_id == currentSemesterId);

  const updatedSchedules = currentSemesterSchedules.map((schedule) => ({
    schedule_id: schedule.schedule_id,
    day_of_week: schedule.day_of_week,
    start_time: schedule.start_time,
    end_time: schedule.end_time,
    course_code: schedule.course_code,
    course_name: schedule.course_name,
    faculty_name: schedule.faculty_name,
    room_name: schedule.room_name || "",
    section_name: schedule.section_name,
    semester_id: schedule.semester_id,
  }));

  fetch("/chair/schedule_management", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ schedules: updatedSchedules }),
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.success) {
        showNotification("All changes saved successfully!", "success");
        window.scheduleData = data.schedules || [];
        safeUpdateScheduleDisplay(window.scheduleData);
        initializeDragAndDrop();
      } else {
        showNotification(data.message || "Failed to save changes.", "error");
      }
    })
    .catch((error) => {
      console.error("Error:", error);
      showNotification("Error saving changes: " + error.message, "error");
    });
}

function toggleViewMode() {
  const gridView = document.getElementById("grid-view");
  const listView = document.getElementById("list-view");
  const toggleBtn = document.getElementById("toggle-view-btn");

  if (gridView.classList.contains("hidden")) {
    gridView.classList.remove("hidden");
    listView.classList.add("hidden");
    toggleBtn.innerHTML =
      '<i class="fas fa-list mr-1"></i><span>List View</span>';
    console.log("Switched to GRID view");
    filterSchedulesManual(); // Apply filters to grid view
  } else {
    gridView.classList.add("hidden");
    listView.classList.remove("hidden");
    toggleBtn.innerHTML =
      '<i class="fas fa-th mr-1"></i><span>Grid View</span>';
    console.log("Switched to LIST view");
    filterSchedulesListView(); // Apply filters to list view
  }
}

function filterSchedulesListView() {
  const yearLevel = document
    .getElementById("filter-year-manual")
    .value.toLowerCase()
    .trim();
  const section = document
    .getElementById("filter-section-manual")
    .value.toLowerCase()
    .trim();
  const room = document
    .getElementById("filter-room-manual")
    .value.toLowerCase()
    .trim();

  const tableRows = document.querySelectorAll(
    "#list-view tbody tr.schedule-row"
  );

  let visibleCount = 0;

  tableRows.forEach((row, index) => {
    const rowYearLevel = (row.getAttribute("data-year-level") || "")
      .toLowerCase()
      .trim();
    const rowSectionName = (row.getAttribute("data-section-name") || "")
      .toLowerCase()
      .trim();
    const rowRoomName = (row.getAttribute("data-room-name") || "")
      .toLowerCase()
      .trim();

    console.log(`Row ${index + 1}:`, {
      rowYearLevel,
      rowSectionName,
      rowRoomName,
    });

    const matchesYear = !yearLevel || rowYearLevel === yearLevel;
    const matchesSection = !section || rowSectionName === section;
    const matchesRoom = !room || rowRoomName === room;

    console.log(`Row ${index + 1} matches:`, {
      matchesYear,
      matchesSection,
      matchesRoom,
      shouldShow: matchesYear && matchesSection && matchesRoom,
    });

    if (matchesYear && matchesSection && matchesRoom) {
      row.style.display = "";
      visibleCount++;
      console.log(`Row ${index + 1}: SHOWING`);
    } else {
      row.style.display = "none";
      console.log(`Row ${index + 1}: HIDING`);
    }
  });

  console.log("Visible rows after filter:", visibleCount);

  const tbody = document.querySelector("#list-view tbody");
  let noResultsRow = tbody.querySelector(".no-results-row");

  if (visibleCount === 0 && tableRows.length > 0) {
    console.log("No rows visible - showing no results message");
    if (!noResultsRow) {
      noResultsRow = document.createElement("tr");
      noResultsRow.className = "no-results-row";
      noResultsRow.innerHTML = `
                <td colspan="8" class="px-4 py-8 text-center text-gray-500">
                    <i class="fas fa-search text-3xl mb-2"></i>
                    <p class="mt-2">No schedules match the selected filters</p>
                    <button onclick="clearFiltersManual()" class="mt-2 px-3 py-1 bg-yellow-500 text-white rounded hover:bg-yellow-600 text-sm">
                        Clear Filters
                    </button>
                </td>
            `;
      tbody.appendChild(noResultsRow);
    }
  } else if (visibleCount > 0 && noResultsRow) {
    noResultsRow.remove();
  }
}

function filterSchedulesManual() {
  const currentView = document
    .getElementById("grid-view")
    .classList.contains("hidden")
    ? "list"
    : "grid";
  console.log("Current view:", currentView);

  if (currentView === "list") {
    filterSchedulesListView();
  } else {
    const yearLevel = document.getElementById("filter-year-manual").value;
    const section = document.getElementById("filter-section-manual").value;
    const room = document.getElementById("filter-room-manual").value;
    console.log("Filtering by:", { yearLevel, section, room });

    const scheduleCards = document.querySelectorAll(
      "#schedule-grid .schedule-card"
    );
    const dropZones = document.querySelectorAll("#schedule-grid .drop-zone");

    scheduleCards.forEach((card) => {
      const cardYearLevel = card.getAttribute("data-year-level");
      const cardSectionName = card.getAttribute("data-section-name");
      const cardRoomName = card.getAttribute("data-room-name");

      const matchesYear = !yearLevel || cardYearLevel === yearLevel;
      const matchesSection = !section || cardSectionName === section;
      const matchesRoom = !room || cardRoomName === room;

      if (matchesYear && matchesSection && matchesRoom) {
        card.style.display = "block";
        card.parentElement.style.display = "block";
      } else {
        card.style.display = "none";
      }
    });

    dropZones.forEach((zone) => {
      const card = zone.querySelector(".schedule-card");
      const addButton = zone.querySelector(
        'button[onclick*="openAddModalForSlot"]'
      );
      if (addButton) {
        if (card && card.style.display === "none") {
          addButton.style.display = "block";
        } else if (card && card.style.display === "block") {
          addButton.style.display = "none";
        } else {
          addButton.style.display = "block";
        }
      }
    });
  }
}


function clearFiltersManual() {
  document.getElementById("filter-year-manual").value = "";
  document.getElementById("filter-section-manual").value = "";
  document.getElementById("filter-room-manual").value = "";
  filterSchedulesManual();
}

function refreshManualView() {
  location.reload();
}

// Initialize event listeners
document.addEventListener("DOMContentLoaded", function () {
  console.log("Manual schedules JS loaded");
  console.log("Current semester:", window.currentSemester);
  console.log("Schedule data count:", window.scheduleData?.length || 0);

  buildCurrentSemesterCourseMappings();
  initializeDragAndDrop();

  const filters = [
    "filter-year-manual",
    "filter-section-manual",
    "filter-room-manual",
  ];

  filters.forEach((filterId) => {
    const filter = document.getElementById(filterId);
    if (filter) {
      filter.addEventListener("change", function () {
        console.log(`Filter changed: ${filterId} = ${this.value}`);
        filterSchedulesManual(); // Trigger filtering based on current view
      });
    }
  });

  // Modal click outside to close
  const modal = document.getElementById("schedule-modal");
  if (modal) {
    modal.addEventListener("click", function (e) {
      if (e.target === modal) closeModal();
    });
  }

  // Delete modal click outside to close
  const deleteModal = document.getElementById("delete-confirmation-modal");
  if (deleteModal) {
    deleteModal.addEventListener("click", function (e) {
      if (e.target === deleteModal) closeDeleteModal();
    });
  }

  // Real-time validation setup
  const facultySelect = document.getElementById("faculty-name");
  if (facultySelect) {
    facultySelect.addEventListener("change", (e) => {
      validateFieldRealTime("faculty_name", e.target.value, {
        day_of_week: document.getElementById("day-select")?.value || "",
        start_time: document.getElementById("start-time")?.value + ":00" || "",
        end_time: document.getElementById("end-time")?.value + ":00" || ""
      });
    });
  }

  const roomSelect = document.getElementById("room-name");
  if (roomSelect) {
    roomSelect.addEventListener("change", (e) => {
      validateFieldRealTime("room_name", e.target.value, {
        day_of_week: document.getElementById("day-select")?.value || "",
        start_time: document.getElementById("start-time")?.value + ":00" || "",
        end_time: document.getElementById("end-time")?.value + ":00" || ""
      });
    });
  }

  const sectionSelect = document.getElementById("section-name");
  if (sectionSelect) {
    sectionSelect.addEventListener("change", (e) => {
      validateFieldRealTime("section_name", e.target.value);
      handleSectionChange();
    });
  }

  const daySelect = document.getElementById("day-select");
  if (daySelect) {
    daySelect.addEventListener("change", (e) => {
      updateDayField();
      validateFieldRealTime("day_of_week", e.target.value, {
        faculty_name: document.getElementById("faculty-name")?.value || "",
        room_name: document.getElementById("room-name")?.value || "",
        start_time: document.getElementById("start-time")?.value + ":00" || "",
        end_time: document.getElementById("end-time")?.value + ":00" || ""
      });
    });
  }

  const startTimeSelect = document.getElementById("start-time");
  if (startTimeSelect) {
    startTimeSelect.addEventListener("change", (e) => {
      updateTimeFields();
      validateFieldRealTime("start_time", e.target.value + ":00", {
        day_of_week: document.getElementById("day-select")?.value || "",
        faculty_name: document.getElementById("faculty-name")?.value || "",
        room_name: document.getElementById("room-name")?.value || ""
      });
    });
  }

  const endTimeSelect = document.getElementById("end-time");
  if (endTimeSelect) {
    endTimeSelect.addEventListener("change", (e) => {
      updateTimeFields();
      validateFieldRealTime("end_time", e.target.value + ":00", {
        day_of_week: document.getElementById("day-select")?.value || "",
        start_time: document.getElementById("start-time")?.value + ":00" || "",
        faculty_name: document.getElementById("faculty-name")?.value || "",
        room_name: document.getElementById("room-name")?.value || ""
      });
    });
  }

  // Add course conflict detection event listeners
  const courseCodeInput = document.getElementById("course-code");
  if (courseCodeInput) {
    courseCodeInput.addEventListener("blur", syncCourseName);
    courseCodeInput.addEventListener("input", function () {
      // Clear conflict warning when user starts typing
      resetConflictField("course-code");
      resetConflictField("course-name");
    });
  }

  const courseNameInput = document.getElementById("course-name");
  if (courseNameInput) {
    courseNameInput.addEventListener("blur", syncCourseCode);
    courseNameInput.addEventListener("input", function () {
      // Clear conflict warning when user starts typing
      resetConflictField("course-code");
      resetConflictField("course-name");
    });
  }

  // Ensure scheduleData is always an array
  if (!Array.isArray(window.scheduleData)) window.scheduleData = [];

  // Initialize with safe display
  setTimeout(() => {
    safeUpdateScheduleDisplay(window.scheduleData);
    setTimeout(() => initializeDragAndDrop(), 100);
  }, 100);

  console.log("Manual schedules initialized successfully");
  console.log("Available courses for current semester:", Object.keys(currentSemesterCourses).length);
});


// Enhanced course conflict detection with friendly messages
function validateCourseConflict(courseCode, courseName, currentScheduleId = null) {
  if (!courseCode || !window.scheduleData || window.scheduleData.length === 0) {
    return null;
  }

  const currentSemesterId = window.currentSemester?.semester_id;
  const enteredCode = courseCode.trim().toUpperCase();
  const enteredName = courseName.trim().toLowerCase();

  // Check if course exists in curriculum
  if (!currentSemesterCourses[enteredCode] && enteredCode) {
    displayConflictWarning("course-code",
      "⚠️ This course code is not in the current semester curriculum. Please verify the code or check if this course should be added to the curriculum.",
      'warning'
    );
  } else {
    removeConflictWarning("course-code");
  }

  // Check for duplicate course codes in the same semester
  const duplicateCourses = window.scheduleData.filter(schedule => {
    if (schedule.semester_id != currentSemesterId) return false;
    if (currentScheduleId && schedule.schedule_id == currentScheduleId) return false;

    const scheduleCode = schedule.course_code?.trim().toUpperCase();
    const scheduleName = schedule.course_name?.trim().toLowerCase();

    return scheduleCode === enteredCode || scheduleName === enteredName;
  });

  if (duplicateCourses.length > 0) {
    const conflictCount = duplicateCourses.length;
    const sampleConflicts = duplicateCourses.slice(0, 2).map(s =>
      `${s.section_name} (${s.day_of_week} ${formatTime(s.start_time?.substring(0, 5))}-${formatTime(s.end_time?.substring(0, 5))})`
    ).join(', ');

    const extraCount = conflictCount > 2 ? ` and ${conflictCount - 2} more` : '';

    const message = `📚 This course is already scheduled in ${conflictCount} section(s): ${sampleConflicts}${extraCount}. Duplicate scheduling may cause conflicts.`;

    return {
      type: 'course_duplicate',
      message: message,
      conflicts: duplicateCourses,
      warningLevel: 'warning' // This is a warning, not an error
    };
  }

  return null;
}

// Add reset function for specific fields
function resetConflictField(fieldId) {
  const field = document.getElementById(fieldId);
  if (field) {
    field.classList.remove("border-red-500", "bg-red-50");
    field.classList.add("border-gray-300");

    const tooltip = field.parentNode.querySelector(".conflict-tooltip");
    if (tooltip) tooltip.remove();
  }
}

// Enhanced conflict display with friendly messages
function displayConflictWarning(fieldId, message, warningLevel = 'warning') {
  const field = document.getElementById(fieldId);
  if (!field) return;

  // Remove existing warning
  removeConflictWarning(fieldId);

  // Add appropriate styling based on warning level
  if (warningLevel === 'error') {
    field.classList.add("border-red-500", "bg-red-50");
    field.classList.remove("border-gray-300", "bg-yellow-50");
  } else {
    field.classList.add("border-yellow-500", "bg-yellow-50");
    field.classList.remove("border-gray-300", "border-red-500", "bg-red-50");
  }

  // Create warning message element
  const warningDiv = document.createElement("div");
  warningDiv.className = `conflict-warning text-${warningLevel === 'error' ? 'red' : 'yellow'}-600 text-xs mt-1 flex items-start space-x-1`;
  warningDiv.innerHTML = `
        <i class="fas fa-exclamation-triangle mt-0.5 flex-shrink-0"></i>
        <span class="flex-1">${message}</span>
    `;

  // Insert after the field
  field.parentNode.appendChild(warningDiv);
}

// Remove specific warning
function removeConflictWarning(fieldId) {
  const field = document.getElementById(fieldId);
  if (!field) return;

  const parent = field.parentNode;
  const existingWarning = parent.querySelector('.conflict-warning');
  if (existingWarning) {
    existingWarning.remove();
  }

  // Reset field styling
  field.classList.remove("border-red-500", "bg-red-50", "border-yellow-500", "bg-yellow-50");
  field.classList.add("border-gray-300");
  field.style.backgroundColor = "";
}

// Dynamic time selection functions
function updateEndTimeOptions() {
    const startTimeSelect = document.getElementById('start-time');
    const endTimeSelect = document.getElementById('end-time');
    const selectedStartTime = startTimeSelect.value;
    
    if (!selectedStartTime) {
        endTimeSelect.innerHTML = '<option value="">Select End Time</option>';
        return;
    }
    
    // Clear existing options
    endTimeSelect.innerHTML = '<option value="">Select End Time</option>';
    
    // Parse selected start time
    const [startHour, startMinute] = selectedStartTime.split(':').map(Number);
    const startTotalMinutes = startHour * 60 + startMinute;
    
    // Generate end time options (30 minutes to 4 hours after start time)
    for (let duration = 30; duration <= 240; duration += 30) {
        const endTotalMinutes = startTotalMinutes + duration;
        const endHour = Math.floor(endTotalMinutes / 60);
        const endMinute = endTotalMinutes % 60;
        
        // Only show times up to 10:00 PM (22:00)
        if (endHour < 22 || (endHour === 22 && endMinute === 0)) {
            const endTimeValue = `${endHour.toString().padStart(2, '0')}:${endMinute.toString().padStart(2, '0')}`;
            const endTimeDisplay = formatTime(endTimeValue);
            const durationText = formatDuration(duration);
            
            const option = document.createElement('option');
            option.value = endTimeValue;
            option.textContent = `${endTimeDisplay} (${durationText})`;
            option.setAttribute('data-duration', duration);
            
            endTimeSelect.appendChild(option);
        }
    }
    
    // Auto-select 1 hour duration if available
    const oneHourOption = endTimeSelect.querySelector('option[data-duration="60"]');
    if (oneHourOption) {
        oneHourOption.selected = true;
    }
    
    updateTimeFields();
}

function formatDuration(minutes) {
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    
    if (hours === 0) {
        return `${mins}min`;
    } else if (mins === 0) {
        return `${hours}h`;
    } else {
        return `${hours}h ${mins}m`;
    }
}

// Enhanced formatTime function
function formatTime(timeString) {
    if (!timeString) return "";
    const [hours, minutes] = timeString.split(":");
    const date = new Date(2000, 0, 1, hours, minutes);
    return date.toLocaleTimeString("en-US", {
        hour: "numeric",
        minute: "2-digit",
        hour12: true,
    });
}

// Enhanced safeUpdateScheduleDisplay for dynamic grid
function safeUpdateScheduleDisplay(schedules) {
    window.scheduleData = schedules;
    
    // Update both manual and view grids
    updateManualGrid(schedules);
    updateViewGrid(schedules);
}

function updateManualGrid(schedules) {
    const manualGrid = document.getElementById("schedule-grid");
    if (!manualGrid) return;
    
    manualGrid.innerHTML = "";
    
    // Generate dynamic time slots (same as PHP)
    const timeSlots = generateTimeSlots();
    const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
    
    // Pre-process schedules for faster lookup
    const scheduleLookup = {};
    schedules.forEach(schedule => {
        const day = schedule.day_of_week;
        const start = schedule.start_time ? schedule.start_time.substring(0, 5) : '';
        const end = schedule.end_time ? schedule.end_time.substring(0, 5) : '';
        
        if (!scheduleLookup[day]) {
            scheduleLookup[day] = [];
        }
        
        scheduleLookup[day].push({
            schedule: schedule,
            start: start,
            end: end
        });
    });
    
    timeSlots.forEach(time => {
        const duration = (new Date(`2000-01-01 ${time[1]}`) - new Date(`2000-01-01 ${time[0]}`)) / 1000;
        const rowSpan = Math.max(1, duration / 1800); // 30-minute base unit
        const minHeight = rowSpan * 60;
        
        const row = document.createElement('div');
        row.className = `grid grid-cols-8 min-h-[${minHeight}px] hover:bg-gray-50 transition-colors duration-200`;
        row.style.gridRow = `span ${rowSpan}`;
        
        // Time cell
        const timeCell = document.createElement('div');
        timeCell.className = 'px-3 py-3 text-sm font-medium text-gray-600 border-r border-gray-200 bg-gray-50 sticky left-0 z-10 flex items-start';
        timeCell.style.gridRow = `span ${rowSpan}`;
        timeCell.innerHTML = `
            <span class="text-sm hidden sm:block">${formatTime(time[0])} - ${formatTime(time[1])}</span>
            <span class="text-xs sm:hidden">${time[0].substring(0, 5)}-${time[1].substring(0, 5)}</span>
        `;
        row.appendChild(timeCell);
        
        // Day cells
        days.forEach(day => {
            const cell = document.createElement('div');
            cell.className = `px-1 py-1 border-r border-gray-200 last:border-r-0 relative drop-zone min-h-[${minHeight}px]`;
            cell.dataset.day = day;
            cell.dataset.startTime = time[0];
            cell.dataset.endTime = time[1];
            
            const schedulesInSlot = [];
            if (scheduleLookup[day]) {
                scheduleLookup[day].forEach(scheduleData => {
                    const scheduleStart = scheduleData.start;
                    const scheduleEnd = scheduleData.end;
                    
                    const slotStart = new Date(`2000-01-01 ${time[0]}`).getTime();
                    const slotEnd = new Date(`2000-01-01 ${time[1]}`).getTime();
                    const schedStart = new Date(`2000-01-01 ${scheduleStart}`).getTime();
                    const schedEnd = new Date(`2000-01-01 ${scheduleEnd}`).getTime();
                    
                    if (schedStart < slotEnd && schedEnd > slotStart) {
                        schedulesInSlot.push({
                            schedule: scheduleData.schedule,
                            isStartCell: (scheduleStart === time[0])
                        });
                    }
                });
            }
            
            if (schedulesInSlot.length === 0) {
                const addButton = document.createElement('button');
                addButton.innerHTML = '<i class="fas fa-plus text-xs"></i>';
                addButton.className = 'w-full h-full text-gray-400 hover:text-gray-600 hover:bg-yellow-50 rounded-lg border-2 border-dashed border-gray-300 hover:border-yellow-400 transition-all duration-200 no-print flex items-center justify-center p-1';
                addButton.onclick = () => openAddModalForSlot(day, time[0], time[1]);
                cell.appendChild(addButton);
            } else {
                const container = document.createElement('div');
                container.className = 'space-y-1 p-1';
                
                schedulesInSlot.forEach(scheduleData => {
                    const scheduleCard = createDynamicScheduleCard(scheduleData.schedule, scheduleData.isStartCell);
                    container.appendChild(scheduleCard);
                });
                
                cell.appendChild(container);
            }
            
            row.appendChild(cell);
        });
        
        manualGrid.appendChild(row);
    });
    
    initializeDragAndDrop();
}

function generateTimeSlots() {
    const timeSlots = [];
    const startHour = 7;
    const endHour = 21;
    
    for (let hour = startHour; hour < endHour; hour++) {
        for (let minute = 0; minute < 60; minute += 30) {
            const currentTime = `${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}`;
            const nextHour = hour + (minute + 30 >= 60 ? 1 : 0);
            const nextMinute = (minute + 30) % 60;
            
            if (nextHour >= endHour && nextMinute > 0) continue;
            
            const nextTime = `${nextHour.toString().padStart(2, '0')}:${nextMinute.toString().padStart(2, '0')}`;
            timeSlots.push([currentTime, nextTime]);
        }
    }
    
    return timeSlots;
}

function createDynamicScheduleCard(schedule, isStartCell) {
    const colors = [
        'bg-blue-100 border-blue-300 text-blue-800',
        'bg-green-100 border-green-300 text-green-800',
        'bg-purple-100 border-purple-300 text-purple-800',
        'bg-orange-100 border-orange-300 text-orange-800',
        'bg-pink-100 border-pink-300 text-pink-800',
        'bg-teal-100 border-teal-300 text-teal-800',
        'bg-amber-100 border-amber-300 text-amber-800'
    ];
    
    const colorIndex = schedule.schedule_id ? (schedule.schedule_id % colors.length) : Math.floor(Math.random() * colors.length);
    const colorClass = colors[colorIndex];
    
    const card = document.createElement('div');
    card.className = `schedule-card ${colorClass} p-2 rounded-lg border-l-4 draggable cursor-move text-xs`;
    card.draggable = true;
    card.dataset.scheduleId = schedule.schedule_id || '';
    card.dataset.yearLevel = schedule.year_level || '';
    card.dataset.sectionName = schedule.section_name || '';
    card.dataset.roomName = schedule.room_name || 'Online';
    
    if (!isStartCell) {
        card.style.opacity = '0.6';
    }
    
    card.innerHTML = `
        ${isStartCell ? `
            <div class="flex justify-between items-start mb-1">
                <div class="font-semibold truncate flex-1">
                    ${schedule.course_code || ''}
                </div>
                <div class="flex space-x-1 flex-shrink-0 ml-1">
                    <button onclick="editSchedule('${schedule.schedule_id || ''}')" class="text-yellow-600 hover:text-yellow-700 no-print">
                        <i class="fas fa-edit text-xs"></i>
                    </button>
                    <button onclick="openDeleteSingleModal(
                        '${schedule.schedule_id || ''}', 
                        '${schedule.course_code || ''}', 
                        '${schedule.section_name || ''}', 
                        '${schedule.day_of_week || ''}', 
                        '${schedule.start_time ? formatTime(schedule.start_time.substring(0, 5)) : ''}', 
                        '${schedule.end_time ? formatTime(schedule.end_time.substring(0, 5)) : ''}'
                    )" class="text-red-600 hover:text-red-700 no-print">
                        <i class="fas fa-trash text-xs"></i>
                    </button>
                </div>
            </div>
            <div class="opacity-90 truncate">
                ${schedule.section_name || ''}
            </div>
            <div class="opacity-75 truncate">
                ${schedule.faculty_name || ''}
            </div>
            <div class="opacity-75 truncate">
                ${schedule.room_name || 'Online'}
            </div>
            <div class="font-medium mt-1 hidden sm:block text-xs">
                ${schedule.start_time && schedule.end_time ? 
                    `${formatTime(schedule.start_time.substring(0, 5))} - ${formatTime(schedule.end_time.substring(0, 5))}` : 
                    ''}
            </div>
        ` : `
            <div class="font-semibold truncate mb-1 text-center opacity-75">
                <i class="fas fa-ellipsis-h text-xs"></i>
            </div>
        `}
    `;
    
    card.ondragstart = handleDragStart;
    card.ondragend = handleDragEnd;
    
    return card;
}

function updateViewGrid(schedules) {
    const viewGrid = document.getElementById('timetableGrid');
    if (!viewGrid) return;
    
    viewGrid.innerHTML = '';
    
    const timeSlots = generateTimeSlots();
    const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
    
    // Pre-process schedules for view grid
    const scheduleLookup = {};
    schedules.forEach(schedule => {
        const day = schedule.day_of_week;
        const start = schedule.start_time ? schedule.start_time.substring(0, 5) : '';
        
        if (!scheduleLookup[day]) {
            scheduleLookup[day] = {};
        }
        if (!scheduleLookup[day][start]) {
            scheduleLookup[day][start] = [];
        }
        scheduleLookup[day][start].push(schedule);
    });
    
    timeSlots.forEach(time => {
        const duration = (new Date(`2000-01-01 ${time[1]}`) - new Date(`2000-01-01 ${time[0]}`)) / 1000;
        const rowSpan = Math.max(1, duration / 1800);
        const minHeight = rowSpan * 60;
        
        const row = document.createElement('div');
        row.className = `grid grid-cols-8 min-h-[${minHeight}px] hover:bg-gray-50 transition-colors duration-200`;
        row.style.gridRow = `span ${rowSpan}`;
        
        // Time cell
        const timeCell = document.createElement('div');
        timeCell.className = 'px-4 py-3 text-sm font-medium text-gray-600 border-r border-gray-200 bg-gray-50 flex items-center';
        timeCell.style.gridRow = `span ${rowSpan}`;
        timeCell.textContent = `${formatTime(time[0])} - ${formatTime(time[1])}`;
        row.appendChild(timeCell);
        
        // Day cells
        days.forEach(day => {
            const cell = document.createElement('div');
            cell.className = `px-2 py-2 border-r border-gray-200 last:border-r-0 min-h-[${minHeight}px] relative schedule-cell`;
            cell.dataset.day = day;
            cell.dataset.startTime = time[0];
            cell.dataset.endTime = time[1];
            
            const daySchedules = scheduleLookup[day] && scheduleLookup[day][time[0]] ? scheduleLookup[day][time[0]] : [];
            
            if (daySchedules.length > 0) {
                const container = document.createElement('div');
                container.className = 'schedules-container space-y-1';
                
                daySchedules.forEach(schedule => {
                    const scheduleItem = createDynamicScheduleItem(schedule);
                    container.appendChild(scheduleItem);
                });
                
                cell.appendChild(container);
            }
            
            row.appendChild(cell);
        });
        
        viewGrid.appendChild(row);
    });
}

function createDynamicScheduleItem(schedule) {
    const colors = [
        'bg-blue-100 border-blue-300 text-blue-800',
        'bg-green-100 border-green-300 text-green-800',
        'bg-purple-100 border-purple-300 text-purple-800',
        'bg-orange-100 border-orange-300 text-orange-800',
        'bg-pink-100 border-pink-300 text-pink-800'
    ];
    
    const colorIndex = schedule.schedule_id ? (schedule.schedule_id % colors.length) : Math.floor(Math.random() * colors.length);
    const colorClass = colors[colorIndex];
    
    const item = document.createElement('div');
    item.className = `schedule-card ${colorClass} p-2 rounded-lg border-l-4 mb-1 schedule-item`;
    item.dataset.yearLevel = schedule.year_level || '';
    item.dataset.sectionName = schedule.section_name || '';
    item.dataset.roomName = schedule.room_name || 'Online';
    
    item.innerHTML = `
        <div class="font-semibold text-xs truncate mb-1">
            ${schedule.course_code || ''}
        </div>
        <div class="text-xs opacity-90 truncate mb-1">
            ${schedule.section_name || ''}
        </div>
        <div class="text-xs opacity-75 truncate">
            ${schedule.faculty_name || ''}
        </div>
        <div class="text-xs opacity-75 truncate">
            ${schedule.room_name || 'Online'}
        </div>
        <div class="text-xs font-medium mt-1">
            ${schedule.start_time && schedule.end_time ? 
                `${formatTime(schedule.start_time.substring(0, 5))} - ${formatTime(schedule.end_time.substring(0, 5))}` : 
                ''}
        </div>
    `;
    
    return item;
}

// Update your existing openAddModalForSlot to set times properly
function openAddModalForSlot(day, startTime, endTime) {
    openAddModal();
    
    document.getElementById("modal-day").value = day;
    document.getElementById("day-select").value = day;
    
    // Set start time and update end time options
    document.getElementById("start-time").value = startTime;
    updateEndTimeOptions();
    
    // Set the specific end time
    document.getElementById("end-time").value = endTime;
    updateTimeFields();
}