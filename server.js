// server.js - Express server for LogRobin++ protocol
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { LogRobinPP } = require('./logrobin');

const app = express();
const port = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'LogRobin++ server is running' });
});

// Protocol execution endpoint
app.post('/api/execute', (req, res) => {
  try {
    const { config, proverInput } = req.body;
    
    // Validate request
    if (!config || !proverInput) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required parameters' 
      });
    }
    
    // Convert numeric values to BigInt where needed
    const processedConfig = {
      ...config,
      fieldModulus: BigInt(config.fieldModulus),
      logger: { level: config.logLevel || 'info', timestamps: true }
    };
    
    const processedInput = {
      ...proverInput,
      witness: proverInput.witness.map(w => BigInt(w))
    };
    
    // Initialize and execute protocol
    console.log(`Executing LogRobin++ protocol with ${config.B} branches`);
    const protocol = new LogRobinPP.LogRobinPlusPlus(processedConfig);
    
    // Capture console output
    const logs = [];
    const originalConsoleLog = console.log;
    console.log = (...args) => {
      logs.push(args.join(' '));
      originalConsoleLog(...args);
    };
    
    // Execute protocol
    const startTime = performance.now();
    const result = protocol.execute(processedInput);
    const endTime = performance.now();
    
    // Restore console
    console.log = originalConsoleLog;
    
    // Add execution time to result
    result.executionTime = Math.round(endTime - startTime);
    result.logs = logs;
    
    // Convert BigInts to strings for JSON serialization
    const serializedResult = JSON.parse(
      JSON.stringify(result, (_, value) => 
        typeof value === 'bigint' ? value.toString() : value
      )
    );
    
    return res.status(200).json(serializedResult);
  } catch (error) {
    console.error('Error executing protocol:', error);
    return res.status(500).json({ 
      success: false, 
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Start server
app.listen(port, () => {
  console.log(`LogRobin++ server listening on port ${port}`);
});