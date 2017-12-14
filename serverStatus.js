> db.serverStatus()
{
	"host" : "triton8",
	"version" : "3.4.9",
	"process" : "mongod",
	"pid" : NumberLong(4053),
	"uptime" : 93756,
	"uptimeMillis" : NumberLong(93756073),
	"uptimeEstimate" : NumberLong(93756),
	"localTime" : ISODate("2017-11-25T08:50:32.189Z"),
	"asserts" : {
		"regular" : 0,
		"warning" : 0,
		"msg" : 0,
		"user" : 0,
		"rollovers" : 0
	},
	"connections" : {
		"current" : 1,
		"available" : 51199,
		"totalCreated" : 1
	},
	"extra_info" : {
		"note" : "fields vary by platform",
		"page_faults" : 0
	},
	"globalLock" : {
		"totalTime" : NumberLong("93756069000"),
		"currentQueue" : {
			"total" : 0,
			"readers" : 0,
			"writers" : 0
		},
		"activeClients" : {
			"total" : 9,
			"readers" : 0,
			"writers" : 0
		}
	},
	"locks" : {
		"Global" : {
			"acquireCount" : {
				"r" : NumberLong(468784),
				"w" : NumberLong(11),
				"W" : NumberLong(3)
			}
		},
		"Database" : {
			"acquireCount" : {
				"r" : NumberLong(187504),
				"R" : NumberLong(4),
				"W" : NumberLong(11)
			}
		},
		"Collection" : {
			"acquireCount" : {
				"r" : NumberLong(187504)
			}
		},
		"Metadata" : {
			"acquireCount" : {
				"w" : NumberLong(1)
			}
		}
	},
	"network" : {
		"bytesIn" : NumberLong(1302),
		"bytesOut" : NumberLong(6042),
		"physicalBytesIn" : NumberLong(1302),
		"physicalBytesOut" : NumberLong(6042),
		"numRequests" : NumberLong(29)
	},
	"opLatencies" : {
		"reads" : {
			"latency" : NumberLong(174),
			"ops" : NumberLong(1)
		},
		"writes" : {
			"latency" : NumberLong(0),
			"ops" : NumberLong(0)
		},
		"commands" : {
			"latency" : NumberLong(531),
			"ops" : NumberLong(13)
		}
	},
	"opcounters" : {
		"insert" : 0,
		"query" : 2,
		"update" : 0,
		"delete" : 0,
		"getmore" : 0,
		"command" : 14
	},
	"opcountersRepl" : {
		"insert" : 0,
		"query" : 0,
		"update" : 0,
		"delete" : 0,
		"getmore" : 0,
		"command" : 0
	},
	"storageEngine" : {
		"name" : "wiredTiger",
		"supportsCommittedReads" : true,
		"readOnly" : false,
		"persistent" : true
	},
	"tcmalloc" : {
		"generic" : {
			"current_allocated_bytes" : 61155856,
			"heap_size" : 66785280
		},
		"tcmalloc" : {
			"pageheap_free_bytes" : 4403200,
			"pageheap_unmapped_bytes" : 57344,
			"max_total_thread_cache_bytes" : 781189120,
			"current_total_thread_cache_bytes" : 491824,
			"total_free_bytes" : 1168880,
			"central_cache_free_bytes" : 187328,
			"transfer_cache_free_bytes" : 489728,
			"thread_cache_free_bytes" : 491824,
			"aggressive_memory_decommit" : 0,
			"formattedString" : "------------------------------------------------\nMALLOC:       61155856 (   58.3 MiB) Bytes in use by application\nMALLOC: +      4403200 (    4.2 MiB) Bytes in page heap freelist\nMALLOC: +       187328 (    0.2 MiB) Bytes in central cache freelist\nMALLOC: +       489728 (    0.5 MiB) Bytes in transfer cache freelist\nMALLOC: +       491824 (    0.5 MiB) Bytes in thread cache freelists\nMALLOC: +      1302720 (    1.2 MiB) Bytes in malloc metadata\nMALLOC:   ------------\nMALLOC: =     68030656 (   64.9 MiB) Actual memory used (physical + swap)\nMALLOC: +        57344 (    0.1 MiB) Bytes released to OS (aka unmapped)\nMALLOC:   ------------\nMALLOC: =     68088000 (   64.9 MiB) Virtual address space used\nMALLOC:\nMALLOC:            509              Spans in use\nMALLOC:             15              Thread heaps in use\nMALLOC:           4096              Tcmalloc page size\n------------------------------------------------\nCall ReleaseFreeMemory() to release freelist memory to the OS (via madvise()).\nBytes released to the OS take up virtual address space but no physical memory.\n"
		}
	},
	"wiredTiger" : {
		"uri" : "statistics:",
		"LSM" : {
			"application work units currently queued" : 0,
			"merge work units currently queued" : 0,
			"rows merged in an LSM tree" : 0,
			"sleep for LSM checkpoint throttle" : 0,
			"sleep for LSM merge throttle" : 0,
			"switch work units currently queued" : 0,
			"tree maintenance operations discarded" : 0,
			"tree maintenance operations executed" : 0,
			"tree maintenance operations scheduled" : 0,
			"tree queue hit maximum" : 0
		},
		"async" : {
			"current work queue length" : 0,
			"maximum work queue length" : 0,
			"number of allocation state races" : 0,
			"number of flush calls" : 0,
			"number of operation slots viewed for allocation" : 0,
			"number of times operation allocation failed" : 0,
			"number of times worker found no work" : 0,
			"total allocations" : 0,
			"total compact calls" : 0,
			"total insert calls" : 0,
			"total remove calls" : 0,
			"total search calls" : 0,
			"total update calls" : 0
		},
		"block-manager" : {
			"blocks pre-loaded" : 12,
			"blocks read" : 37,
			"blocks written" : 23,
			"bytes read" : 176128,
			"bytes written" : 143360,
			"bytes written for checkpoint" : 143360,
			"mapped blocks read" : 0,
			"mapped bytes read" : 0
		},
		"cache" : {
			"application threads page read from disk to cache count" : 11,
			"application threads page read from disk to cache time (usecs)" : 98,
			"application threads page write from cache to disk count" : 0,
			"application threads page write from cache to disk time (usecs)" : 0,
			"bytes belonging to page images in the cache" : 60930,
			"bytes currently in the cache" : 105437,
			"bytes not belonging to page images in the cache" : 44506,
			"bytes read into cache" : 56417,
			"bytes written from cache" : 79139,
			"checkpoint blocked page eviction" : 0,
			"eviction calls to get a page" : 3,
			"eviction calls to get a page found queue empty" : 3,
			"eviction calls to get a page found queue empty after locking" : 0,
			"eviction currently operating in aggressive mode" : 0,
			"eviction empty score" : 0,
			"eviction server candidate queue empty when topping up" : 0,
			"eviction server candidate queue not empty when topping up" : 0,
			"eviction server evicting pages" : 0,
			"eviction server slept, because we did not make progress with eviction" : 0,
			"eviction server unable to reach eviction goal" : 0,
			"eviction state" : 16,
			"eviction walks abandoned" : 0,
			"eviction worker thread active" : 0,
			"eviction worker thread created" : 0,
			"eviction worker thread evicting pages" : 0,
			"eviction worker thread removed" : 0,
			"eviction worker thread stable number" : 0,
			"failed eviction of pages that exceeded the in-memory maximum" : 0,
			"files with active eviction walks" : 0,
			"files with new eviction walks started" : 0,
			"force re-tuning of eviction workers once in a while" : 0,
			"hazard pointer blocked page eviction" : 0,
			"hazard pointer check calls" : 0,
			"hazard pointer check entries walked" : 0,
			"hazard pointer maximum array length" : 0,
			"in-memory page passed criteria to be split" : 0,
			"in-memory page splits" : 0,
			"internal pages evicted" : 0,
			"internal pages split during eviction" : 0,
			"leaf pages split during eviction" : 0,
			"lookaside table insert calls" : 0,
			"lookaside table remove calls" : 0,
			"maximum bytes configured" : 2591031296,
			"maximum page size at eviction" : 0,
			"modified pages evicted" : 0,
			"modified pages evicted by application threads" : 0,
			"overflow pages read into cache" : 0,
			"overflow values cached in memory" : 0,
			"page split during eviction deepened the tree" : 0,
			"page written requiring lookaside records" : 0,
			"pages currently held in the cache" : 26,
			"pages evicted because they exceeded the in-memory maximum" : 0,
			"pages evicted because they had chains of deleted items" : 0,
			"pages evicted by application threads" : 0,
			"pages queued for eviction" : 0,
			"pages queued for urgent eviction" : 0,
			"pages queued for urgent eviction during walk" : 0,
			"pages read into cache" : 24,
			"pages read into cache requiring lookaside entries" : 0,
			"pages requested from the cache" : 315,
			"pages seen by eviction walk" : 0,
			"pages selected for eviction unable to be evicted" : 0,
			"pages walked for eviction" : 0,
			"pages written from cache" : 11,
			"pages written requiring in-memory restoration" : 0,
			"percentage overhead" : 8,
			"tracked bytes belonging to internal pages in the cache" : 19498,
			"tracked bytes belonging to leaf pages in the cache" : 85939,
			"tracked dirty bytes in the cache" : 0,
			"tracked dirty pages in the cache" : 0,
			"unmodified pages evicted" : 0
		},
		"connection" : {
			"auto adjusting condition resets" : 18,
			"auto adjusting condition wait calls" : 562460,
			"detected system time went backwards" : 0,
			"files currently open" : 17,
			"memory allocations" : 1316275,
			"memory frees" : 1315315,
			"memory re-allocations" : 375150,
			"pthread mutex condition wait calls" : 1509165,
			"pthread mutex shared lock read-lock calls" : 562656,
			"pthread mutex shared lock write-lock calls" : 93783,
			"total fsync I/Os" : 31,
			"total read I/Os" : 682,
			"total write I/Os" : 38
		},
		"cursor" : {
			"cursor create calls" : 46,
			"cursor insert calls" : 15,
			"cursor next calls" : 120,
			"cursor prev calls" : 10,
			"cursor remove calls" : 1,
			"cursor reset calls" : 293,
			"cursor restarted searches" : 0,
			"cursor search calls" : 335,
			"cursor search near calls" : 1,
			"cursor update calls" : 0,
			"truncate calls" : 0
		},
		"data-handle" : {
			"connection data handles currently active" : 14,
			"connection sweep candidate became referenced" : 0,
			"connection sweep dhandles closed" : 0,
			"connection sweep dhandles removed from hash list" : 3,
			"connection sweep time-of-death sets" : 3,
			"connection sweeps" : 9375,
			"session dhandles swept" : 0,
			"session sweep attempts" : 15
		},
		"lock" : {
			"checkpoint lock acquisitions" : 3,
			"checkpoint lock application thread wait time (usecs)" : 0,
			"checkpoint lock internal thread wait time (usecs)" : 2,
			"handle-list lock eviction thread wait time (usecs)" : 125338,
			"metadata lock acquisitions" : 3,
			"metadata lock application thread wait time (usecs)" : 0,
			"metadata lock internal thread wait time (usecs)" : 0,
			"schema lock acquisitions" : 18,
			"schema lock application thread wait time (usecs)" : 0,
			"schema lock internal thread wait time (usecs)" : 0,
			"table lock acquisitions" : 0,
			"table lock application thread time waiting for the table lock (usecs)" : 0,
			"table lock internal thread time waiting for the table lock (usecs)" : 0
		},
		"log" : {
			"busy returns attempting to switch slots" : 0,
			"consolidated slot closures" : 8,
			"consolidated slot join active slot closed" : 0,
			"consolidated slot join races" : 0,
			"consolidated slot join transitions" : 8,
			"consolidated slot joins" : 10,
			"consolidated slot transitions unable to find free slot" : 0,
			"consolidated slot unbuffered writes" : 0,
			"log bytes of payload data" : 3503,
			"log bytes written" : 4864,
			"log files manually zero-filled" : 0,
			"log flush operations" : 935575,
			"log force write operations" : 1029318,
			"log force write operations skipped" : 1029315,
			"log records compressed" : 4,
			"log records not compressed" : 0,
			"log records too small to compress" : 6,
			"log release advances write LSN" : 5,
			"log scan operations" : 5,
			"log scan records requiring two reads" : 0,
			"log server thread advances write LSN" : 3,
			"log server thread write LSN walk skipped" : 94734,
			"log sync operations" : 8,
			"log sync time duration (usecs)" : 2092672,
			"log sync_dir operations" : 1,
			"log sync_dir time duration (usecs)" : 6,
			"log write operations" : 10,
			"logging bytes consolidated" : 4480,
			"maximum log file size" : 104857600,
			"number of pre-allocated log files to create" : 2,
			"pre-allocated log files not ready and missed" : 1,
			"pre-allocated log files prepared" : 2,
			"pre-allocated log files used" : 0,
			"records processed by log scan" : 10,
			"total in-memory size of compressed records" : 6110,
			"total log buffer size" : 33554432,
			"total size of compressed records" : 3359,
			"written slots coalesced" : 0,
			"yields waiting for previous log file close" : 0
		},
		"reconciliation" : {
			"fast-path pages deleted" : 0,
			"page reconciliation calls" : 11,
			"page reconciliation calls for eviction" : 0,
			"pages deleted" : 0,
			"split bytes currently awaiting free" : 0,
			"split objects currently awaiting free" : 0
		},
		"session" : {
			"open cursor count" : 30,
			"open session count" : 16,
			"table alter failed calls" : 0,
			"table alter successful calls" : 0,
			"table alter unchanged and skipped" : 0,
			"table compact failed calls" : 0,
			"table compact successful calls" : 0,
			"table create failed calls" : 0,
			"table create successful calls" : 0,
			"table drop failed calls" : 0,
			"table drop successful calls" : 0,
			"table rebalance failed calls" : 0,
			"table rebalance successful calls" : 0,
			"table rename failed calls" : 0,
			"table rename successful calls" : 0,
			"table salvage failed calls" : 0,
			"table salvage successful calls" : 0,
			"table truncate failed calls" : 0,
			"table truncate successful calls" : 0,
			"table verify failed calls" : 0,
			"table verify successful calls" : 0
		},
		"thread-state" : {
			"active filesystem fsync calls" : 0,
			"active filesystem read calls" : 0,
			"active filesystem write calls" : 0
		},
		"thread-yield" : {
			"application thread time evicting (usecs)" : 0,
			"application thread time waiting for cache (usecs)" : 0,
			"page acquire busy blocked" : 0,
			"page acquire eviction blocked" : 0,
			"page acquire locked blocked" : 0,
			"page acquire read blocked" : 0,
			"page acquire time sleeping (usecs)" : 0
		},
		"transaction" : {
			"number of named snapshots created" : 0,
			"number of named snapshots dropped" : 0,
			"transaction begins" : 6,
			"transaction checkpoint currently running" : 0,
			"transaction checkpoint generation" : 3,
			"transaction checkpoint max time (msecs)" : 1533,
			"transaction checkpoint min time (msecs)" : 140,
			"transaction checkpoint most recent time (msecs)" : 394,
			"transaction checkpoint scrub dirty target" : 0,
			"transaction checkpoint scrub time (msecs)" : 0,
			"transaction checkpoint total time (msecs)" : 2067,
			"transaction checkpoints" : 3,
			"transaction checkpoints skipped because database was clean" : 1560,
			"transaction failures due to cache overflow" : 0,
			"transaction fsync calls for checkpoint after allocating the transaction ID" : 3,
			"transaction fsync duration for checkpoint after allocating the transaction ID (usecs)" : 0,
			"transaction range of IDs currently pinned" : 0,
			"transaction range of IDs currently pinned by a checkpoint" : 0,
			"transaction range of IDs currently pinned by named snapshots" : 0,
			"transaction sync calls" : 0,
			"transactions committed" : 2,
			"transactions rolled back" : 4
		},
		"concurrentTransactions" : {
			"write" : {
				"out" : 0,
				"available" : 128,
				"totalTickets" : 128
			},
			"read" : {
				"out" : 1,
				"available" : 127,
				"totalTickets" : 128
			}
		}
	},
	"mem" : {
		"bits" : 64,
		"resident" : 64,
		"virtual" : 948,
		"supported" : true,
		"mapped" : 0,
		"mappedWithJournal" : 0
	},
	"metrics" : {
		"commands" : {
			"buildInfo" : {
				"failed" : NumberLong(0),
				"total" : NumberLong(2)
			},
			"find" : {
				"failed" : NumberLong(0),
				"total" : NumberLong(1)
			},
			"getLog" : {
				"failed" : NumberLong(0),
				"total" : NumberLong(1)
			},
			"isMaster" : {
				"failed" : NumberLong(0),
				"total" : NumberLong(8)
			},
			"replSetGetStatus" : {
				"failed" : NumberLong(1),
				"total" : NumberLong(1)
			},
			"serverStatus" : {
				"failed" : NumberLong(0),
				"total" : NumberLong(1)
			},
			"whatsmyuri" : {
				"failed" : NumberLong(0),
				"total" : NumberLong(1)
			}
		},
		"cursor" : {
			"timedOut" : NumberLong(0),
			"open" : {
				"noTimeout" : NumberLong(0),
				"pinned" : NumberLong(0),
				"total" : NumberLong(0)
			}
		},
		"document" : {
			"deleted" : NumberLong(0),
			"inserted" : NumberLong(0),
			"returned" : NumberLong(0),
			"updated" : NumberLong(0)
		},
		"getLastError" : {
			"wtime" : {
				"num" : 0,
				"totalMillis" : 0
			},
			"wtimeouts" : NumberLong(0)
		},
		"operation" : {
			"scanAndOrder" : NumberLong(0),
			"writeConflicts" : NumberLong(0)
		},
		"queryExecutor" : {
			"scanned" : NumberLong(0),
			"scannedObjects" : NumberLong(0)
		},
		"record" : {
			"moves" : NumberLong(0)
		},
		"repl" : {
			"executor" : {
				"counters" : {
					"eventCreated" : 0,
					"eventWait" : 0,
					"cancels" : 0,
					"waits" : 0,
					"scheduledNetCmd" : 0,
					"scheduledDBWork" : 0,
					"scheduledXclWork" : 0,
					"scheduledWorkAt" : 0,
					"scheduledWork" : 0,
					"schedulingFailures" : 0
				},
				"queues" : {
					"networkInProgress" : 0,
					"dbWorkInProgress" : 0,
					"exclusiveInProgress" : 0,
					"sleepers" : 0,
					"ready" : 0,
					"free" : 0
				},
				"unsignaledEvents" : 0,
				"eventWaiters" : 0,
				"shuttingDown" : false,
				"networkInterface" : "\nNetworkInterfaceASIO Operations' Diagnostic:\nOperation:    Count:   \nConnecting    0        \nIn Progress   0        \nSucceeded     0        \nCanceled      0        \nFailed        0        \nTimed Out     0        \n\n"
			},
			"apply" : {
				"attemptsToBecomeSecondary" : NumberLong(0),
				"batches" : {
					"num" : 0,
					"totalMillis" : 0
				},
				"ops" : NumberLong(0)
			},
			"buffer" : {
				"count" : NumberLong(0),
				"maxSizeBytes" : NumberLong(0),
				"sizeBytes" : NumberLong(0)
			},
			"initialSync" : {
				"completed" : NumberLong(0),
				"failedAttempts" : NumberLong(0),
				"failures" : NumberLong(0)
			},
			"network" : {
				"bytes" : NumberLong(0),
				"getmores" : {
					"num" : 0,
					"totalMillis" : 0
				},
				"ops" : NumberLong(0),
				"readersCreated" : NumberLong(0)
			},
			"preload" : {
				"docs" : {
					"num" : 0,
					"totalMillis" : 0
				},
				"indexes" : {
					"num" : 0,
					"totalMillis" : 0
				}
			}
		},
		"storage" : {
			"freelist" : {
				"search" : {
					"bucketExhausted" : NumberLong(0),
					"requests" : NumberLong(0),
					"scanned" : NumberLong(0)
				}
			}
		},
		"ttl" : {
			"deletedDocuments" : NumberLong(0),
			"passes" : NumberLong(1562)
		}
	},
	"ok" : 1
}
>
