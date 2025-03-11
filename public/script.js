document.getElementById('data-structure').addEventListener('click', function() {
  fetchData();
});

function fetchData() {
  fetch('/api/data')
    .then(response => response.json())
    .then(data => {
      console.log(data);
      // Handle the data in the frontend
    })
    .catch(error => {
      console.error('Error fetching data:', error);
    });
}

