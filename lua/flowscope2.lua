local lm = require "libmoon"
local device = require "device"
local ffi = require "ffi"
local log = require "log"
local flowtracker = require "flowtracker2"
local qq = require "qq"

local jit = require "jit"
jit.opt.start("maxrecord=20000", "maxirconst=20000", "loopunroll=4000")

function configure(parser)
    parser:argument("module", "Path to user-defined analysis module")
    parser:argument("dev", "Devices to use."):args("+"):convert(tonumber)
    parser:option("--size", "Storage capacity of the in-memory ring buffer in GiB."):convert(tonumber):default("8")
    parser:option("--rate", "Rate of the generated traffic in buckets/s."):convert(tonumber):default("10")
    parser:option("--rx-threads", "Number of rx threads per device. If --generate is given, then number of traffic generator threads."):convert(tonumber):default("1"):target("rxThreads")
    parser:option("--analyze-threads", "Number of analyzer threads."):convert(tonumber):default("1"):target("analyzeThreads")
    parser:option("--dump-threads", "Number of dump threads."):convert(tonumber):default("1"):target("dumperThreads")
    parser:option("--path", "Path for output pcaps."):default(".")
    parser:option("--log-level", "Log level"):default("WARN"):target("logLevel")
    parser:option("--max-rules", "Maximum number of rules"):convert(tonumber):default("100"):target("maxRules")
    parser:flag("--generate", "Generate traffic instead of reading from a device"):default(False)
    parser:option("-p --api-port", "Port for the HTTP REST api."):convert(tonumber):default("8000"):target("apiPort")
    parser:option("-b --api-bind", "Bind to a specific IP address. (for example 127.0.0.1)"):target("apiAddress")
    parser:option("-t --api-token", "Token for authorization to api."):default("hardToGuess"):target("apiToken"):count("*")
    local args = parser:parse()
    return args
end


function master(args)
    local f, err = loadfile(args.module)
    if f == nil then
        log:error(err)
    end
    local userModule = f()
    local tracker = flowtracker.new(userModule)

    -- this part should be wrapped by flowscope and exposed via CLI arguments
    for i, dev in ipairs(args.dev) do
        args.dev[i] = device.config{
            port = dev,
            rxQueues = args.rxThreads,
            rssQueues = args.rxThreads
        }
        -- Create analyzers
        for threadId = 0, args.rxThreads - 1 do
            -- get from QQ or from a device queue
            if userModule.mode == "qq" then
                local q = qq.createQQ(args.size)
                table.insert(tracker.qq, q)
                tracker:startNewInserter(args.dev[i]:getRxQueue(threadId), q)
                tracker:startNewDumper(args.path, q)
                tracker:startNewAnalyzer(args.module, q)
            else
                tracker:startNewAnalyzer(args.module, args.dev[i]:getRxQueue(threadId))
            end
        end
        -- Start checker, has to done after the analyzers/pipes are created
        tracker:startChecker(args.module)
    end
    device.waitForLinks()
    -- end wrapped part
    lm.waitForTasks()
    tracker:delete()
    log:info("[master]: Shutdown")
end
