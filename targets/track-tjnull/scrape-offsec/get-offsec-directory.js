// Run this on the browser in Offsec

((document, window) => {

const machines = [];
const listItems = Array.from(document.querySelectorAll('tr.learning-unit-row'));

listItems.forEach(row => {

  // Run this in your browser console on the Proving Grounds machines page
  const nameEl = row.querySelector('[data-test-id="machineName"]');
  if (!nameEl) return;

  const name = nameEl.textContent.trim();
  
  // Get OS type from icon - check for fa-linux or fa-windows class
  const icons = row.querySelector('.name-cell i');
  let os = 'Unknown';
  if (icons) {
    const classes = icons.className;
    if (classes.includes('fa-linux')) os = 'Linux';
    else if (classes.includes('fa-windows')) os = 'Windows';
  }
  
  // Get points
  const pointsEl = row.querySelector('[data-test-id="machinePoints"]');
  const points = pointsEl ? parseInt(pointsEl.textContent.trim()) : 0;
  
  // Get difficulty text
  const diffEl = row.querySelector('[data-test-id="machineDificultyLvl"]');
  const difficultyText = diffEl ? diffEl.textContent.trim() : 'Unknown';
  
  // Adjusted difficulty based on points
  let adjustedDifficulty;
  if (points <= 10) adjustedDifficulty = 'Easy';
  else if (points <= 20) adjustedDifficulty = 'Intermediate';
  else if (points <= 25) adjustedDifficulty = 'Hard';
  else adjustedDifficulty = 'Very Hard';
  
  // Get machine ID from item-id attribute
  const actionDiv = row.querySelector('[item-id]');
  const machineId = actionDiv ? actionDiv.getAttribute('item-id') : null;
  const link = machineId 
    ? `https://portal.offsec.com/machine/${name.toLowerCase()}-${machineId}/overview/details` 
    : null;

  // Get release date - check common locations
  // You may need to adjust this selector based on where the date appears
  const dateEl = row.querySelector('[data-test-id="machineReleaseDate"]') 
    || row.querySelector('.release-date')
    || row.querySelector('td:nth-child(5) span'); // adjust index if needed
  const releaseDate = dateEl ? dateEl.textContent.trim() : null;

  machines.push({
    name,
    os,
    points,
    difficultyText,
    adjustedDifficulty,
    link,
    releaseDate
  });
});

// Output
console.log(JSON.stringify(machines, null, 2));

// Copy to clipboard
copy(machines);
console.log(`\n✓ Scraped ${machines.length} machines and copied to clipboard!`);

})(document,window)
