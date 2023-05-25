# Backend Intelligent Proxy Server

## RESFful Distributed system spec

features:

1. CRAB to bigchaindb
2. Consensus using DemocracyJS
3. Auth system using JWT
4. HTTP Client using ExpressJS
5. more...

## Project setup

```
npm install
```

### Run

```
npm run start
```

```
npm run dev
```

## Directory Layout

```bash
.
│   /abstracts                          # Abstract classes
│   └── /AbstractRouter.js              # Abstract Router that new routers can extend
│   /bin                                # For scripts and entrypoints
│   └── /www.js                         # Node.js server (entry point)
│   /configs                            # JSON/YAML configs
│   ├── /asset.config.json              # BigchainDB Asset config
│   ├── /bigchaindb.config.json         # BigchainDB Server config
│   ├── /httperror.config.json          # Http Error codes with client messages
│   └── /logger.config.json             # Logger(Winston) config
│   └── /ErrorHandler.js                # Basic express error handler
│   /routers                            # Application routers
│   └── /AssetCRABRouter.js             # Basic BigchainDB CRAB router extending AbstractRouter
│   /services/                          # Data services and other shared utilities
│   ├── /CRABServices.js                # Basic BigchainDB CRAB services
│   ├── /LoggerService.js               # Logger(winston) service
│   └── /ORMService.js                  # BigchainDB ORM services setup
│   └── /App.js                             # Express.js application
└── package.json                            # List of project dependencies
```
