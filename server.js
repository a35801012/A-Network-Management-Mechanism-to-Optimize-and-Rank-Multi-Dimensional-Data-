const express = require('express');
const { spawn } = require('child_process');
const app = express();
const port = 3000;

app.use(express.static('public'));

app.get('/api/nic-info', (req, res) => {
  console.log('Attempting to run C program...');
  const cProgram = spawn('./cityfmtop'); // Make sure the path to the C program is correct

  let outputData = '';

  cProgram.stdout.on('data', (data) => {
    console.log('C program stdout:', data.toString());
    outputData += data.toString();
  });

  cProgram.stderr.on('data', (data) => {
    console.error('C program stderr:', data.toString());
  });

  cProgram.on('close', (code) => {
    console.log(`C program exited with code ${code}`);
    if (code === 0) {
      try {
        const parsedOutput = JSON.parse(outputData);
        res.json(parsedOutput);
      } catch (error) {
        console.error('Failed to parse C program output:', error);
        res.status(500).json({ error: 'Failed to parse C program output.' });
      }
    } else {
      res.status(500).json({ error: 'C program did not exit cleanly.' });
    }
  });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

