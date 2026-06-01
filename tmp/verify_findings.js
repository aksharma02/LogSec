const fs = require('fs');
const path = require('path');
const { parseLogFile } = require('../lib/parsers');
const { 
  ruleSoapApiFault, 
  ruleRateLimitAlert, 
  ruleSocketBindFailure, 
  ruleAppCriticalException, 
  ruleResourceExhaustion 
} = require('../lib/rules');

const oracleLogPath = path.join(__dirname, 'uploads', '4f91e2e0-f4e1-41a6-a1dc-959b81ced552_1780316747645__2010-04-24_075154_393__DEBUG_-__ma.txt');
const shutdownLogPath = path.join(__dirname, 'uploads', 'bddcca88-b148-49d6-aadb-be4071dab824_1780316385686_shutdown_log.txt');

console.log('=== ORACLE LOG TEST ===');
if (fs.existsSync(oracleLogPath)) {
  const content = fs.readFileSync(oracleLogPath, 'utf8');
  const parsed = parseLogFile(content, 'session-oracle-123');
  console.log(`Parsed: ${parsed.length} entries.`);
  const soapFaults = ruleSoapApiFault(parsed, 'session-oracle-123');
  const rateLimits = ruleRateLimitAlert(parsed, 'session-oracle-123');
  console.log(`SOAP Faults detected: ${soapFaults.length}`);
  console.log(`Rate limits detected: ${rateLimits.length}`);
  if (soapFaults.length > 0) {
    console.log('Sample SOAP Finding Title:', soapFaults[0].title);
    console.log('Sample SOAP Finding Description:', soapFaults[0].description);
  }
} else {
  console.log(`File not found at: ${oracleLogPath}`);
}

console.log('\n=== SHUTDOWN LOG TEST ===');
if (fs.existsSync(shutdownLogPath)) {
  const content = fs.readFileSync(shutdownLogPath, 'utf8');
  const parsed = parseLogFile(content, 'session-shutdown-123');
  console.log(`Parsed: ${parsed.length} entries.`);
  const socketConflicts = ruleSocketBindFailure(parsed, 'session-shutdown-123');
  const dbErrors = ruleAppCriticalException(parsed, 'session-shutdown-123');
  const resources = ruleResourceExhaustion(parsed, 'session-shutdown-123');
  console.log(`Socket conflicts detected: ${socketConflicts.length}`);
  console.log(`Exceptions & DB errors detected: ${dbErrors.length}`);
  console.log(`Resource warnings detected: ${resources.length}`);
  if (socketConflicts.length > 0) {
    console.log('Sample Socket Finding Title:', socketConflicts[0].title);
  }
  if (dbErrors.length > 0) {
    console.log('Sample Exception Finding Title:', dbErrors[0].title);
  }
} else {
  console.log(`File not found at: ${shutdownLogPath}`);
}
