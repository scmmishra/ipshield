This is a toy example of how you can use IPShield in production with NodeJS

1. No additional packages are required as we're using the built-in dns module
2. Replace "your-ipshield-server.com" with your actual IPShield server address
3. Implement error handling and potentially add retry logic for production use

```js
const dns = require('dns');

function checkIP(ip) {
  return new Promise((resolve, reject) => {
    const resolver = new dns.Resolver();
    resolver.setServers(['your-ipshield-server.com']);

    resolver.resolveTxt(ip, (err, records) => {
      if (err) {
        reject(`Error checking IP: ${err.message}`);
      } else {
        resolve(records[0][0]);
      }
    });
  });
}

async function main() {
  const ip = "8.8.8.8";
  try {
    const result = await checkIP(ip);
    console.log(`IP ${ip} status: ${result}`);
  } catch (error) {
    console.error(`Error: ${error}`);
  }
}

main();
```
