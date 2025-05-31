using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;

public class CryptoMinerWithWallet
{
    private TcpClient client;
    private NetworkStream stream;
    private StreamReader reader;
    private StreamWriter writer;
    private bool isConnected = false;
    private bool isMining = false;
    private bool isAuthenticated = false;
    private string currentHash = "";
    private string currentTarget = "";
    private int hashLength = 6;
    private double miningReward = 0.0;
    private long totalAttempts = 0;
    private CancellationTokenSource miningCancellation;
    private readonly object lockObject = new object();
    
    // User session info
    private string sessionId = "";
    private string username = "";
    private string walletAddress = "";
    private double walletBalance = 0.0;
    
    private readonly string serverHost;
    private readonly int serverPort;
    private readonly int threadCount;
    
    // Pre-allocated character array for performance
    private static readonly char[] chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray();
    
    // Thread-local storage for better performance
    private readonly ThreadLocal<Random> threadLocalRandom = new ThreadLocal<Random>(() => new Random(Guid.NewGuid().GetHashCode()));
    private readonly ThreadLocal<StringBuilder> threadLocalStringBuilder = new ThreadLocal<StringBuilder>(() => new StringBuilder(12));
    private readonly ThreadLocal<SHA256> threadLocalSHA256 = new ThreadLocal<SHA256>(() => SHA256.Create());
    
    public CryptoMinerWithWallet(string host = "0.0.0.0", int port = 598)
    {
        serverHost = host;
        serverPort = port;
        threadCount = Environment.ProcessorCount;
        Console.WriteLine($"🔥 High-Performance Miner with Wallet initialized with {threadCount} threads!");
    }
    
    public async Task StartAsync()
    {
        Console.WriteLine("🚀 HIGH-PERFORMANCE Crypto Miner with Wallet Starting...");
        Console.WriteLine($"💪 Using {threadCount} CPU cores for maximum performance");
        Console.WriteLine($"🎯 Connecting to {serverHost}:{serverPort}");
        Console.WriteLine("=" + new string('=', 60));
        
        while (true)
        {
            try
            {
                await ConnectToServer();
                await AuthenticateUser();
                
                if (isAuthenticated)
                {
                    await ListenForMessages();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Connection error: {ex.Message}");
                Console.WriteLine("🔄 Retrying in 5 seconds...");
                await Task.Delay(5000);
                isAuthenticated = false;
                sessionId = "";
            }
        }
    }
    
    private async Task ConnectToServer()
    {
        client = new TcpClient();
        await client.ConnectAsync(serverHost, serverPort);
        stream = client.GetStream();
        reader = new StreamReader(stream);
        writer = new StreamWriter(stream) { AutoFlush = true };
        isConnected = true;
        
        Console.WriteLine("✅ Connected to mining server!");
        
        // Read welcome message
        string welcomeMsg = await reader.ReadLineAsync();
        if (welcomeMsg != null)
        {
            try
            {
                using JsonDocument doc = JsonDocument.Parse(welcomeMsg);
                JsonElement root = doc.RootElement;
                
                if (root.GetProperty("type").GetString() == "welcome")
                {
                    var serverInfo = root.GetProperty("data").GetProperty("server_info");
                    hashLength = serverInfo.GetProperty("hash_length").GetInt32();
                    miningReward = serverInfo.GetProperty("mining_reward").GetDouble();
                    
                    Console.WriteLine($"💰 Mining reward: {miningReward} coins per solution");
                    Console.WriteLine($"🔍 Hash difficulty: {hashLength} characters");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️  Could not parse welcome message: {ex.Message}");
            }
        }
    }
    
    private async Task AuthenticateUser()
    {
        Console.WriteLine("\n🔐 WALLET AUTHENTICATION REQUIRED");
        Console.WriteLine("═══════════════════════════════════");
        
        while (!isAuthenticated && isConnected)
        {
            Console.WriteLine("\n1. Login to existing account");
            Console.WriteLine("2. Create new account");
            Console.Write("Choose option (1 or 2): ");
            
            string choice = Console.ReadLine();
            
            if (choice == "1")
            {
                await LoginUser();
            }
            else if (choice == "2")
            {
                await RegisterUser();
            }
            else
            {
                Console.WriteLine("❌ Invalid choice. Please enter 1 or 2.");
            }
        }
    }
    
    private async Task RegisterUser()
    {
        Console.WriteLine("\n📝 CREATE NEW ACCOUNT");
        Console.WriteLine("─────────────────────");
        
        Console.Write("Enter desired username: ");
        string newUsername = Console.ReadLine();
        
        if (string.IsNullOrWhiteSpace(newUsername))
        {
            Console.WriteLine("❌ Username cannot be empty");
            return;
        }
        
        Console.Write("Enter password: ");
        string newPassword = ReadPasswordFromConsole();
        
        if (string.IsNullOrWhiteSpace(newPassword))
        {
            Console.WriteLine("❌ Password cannot be empty");
            return;
        }
        
        Console.Write("Confirm password: ");
        string confirmPassword = ReadPasswordFromConsole();
        
        if (newPassword != confirmPassword)
        {
            Console.WriteLine("❌ Passwords do not match");
            return;
        }
        
        // Send registration request
        var registerMessage = new
        {
            type = "register",
            username = newUsername,
            password = newPassword
        };
        
        await writer.WriteLineAsync(JsonSerializer.Serialize(registerMessage));
        
        // Wait for response
        string response = await reader.ReadLineAsync();
        if (response != null)
        {
            await ProcessAuthResponse(response, "register_response");
        }
    }
    
    private async Task LoginUser()
    {
        Console.WriteLine("\n🔑 LOGIN TO ACCOUNT");
        Console.WriteLine("──────────────────");
        
        Console.Write("Username: ");
        string loginUsername = Console.ReadLine();
        
        if (string.IsNullOrWhiteSpace(loginUsername))
        {
            Console.WriteLine("❌ Username cannot be empty");
            return;
        }
        
        Console.Write("Password: ");
        string loginPassword = ReadPasswordFromConsole();
        
        if (string.IsNullOrWhiteSpace(loginPassword))
        {
            Console.WriteLine("❌ Password cannot be empty");
            return;
        }
        
        // Send login request
        var loginMessage = new
        {
            type = "login",
            username = loginUsername,
            password = loginPassword
        };
        
        await writer.WriteLineAsync(JsonSerializer.Serialize(loginMessage));
        
        // Wait for response
        string response = await reader.ReadLineAsync();
        if (response != null)
        {
            await ProcessAuthResponse(response, "login_response");
        }
    }
    
    private async Task ProcessAuthResponse(string response, string expectedType)
    {
        try
        {
            using JsonDocument doc = JsonDocument.Parse(response);
            JsonElement root = doc.RootElement;
            
            if (root.GetProperty("type").GetString() == expectedType)
            {
                var data = root.GetProperty("data");
                bool success = data.GetProperty("success").GetBoolean();
                string message = data.GetProperty("message").GetString();
                
                if (success)
                {
                    Console.WriteLine($"✅ {message}");
                    
                    if (expectedType == "login_response")
                    {
                        // Store session info
                        sessionId = data.GetProperty("session_id").GetString();
                        username = data.GetProperty("username").GetString();
                        walletAddress = data.GetProperty("wallet_address").GetString();
                        walletBalance = data.GetProperty("balance").GetDouble();
                        
                        isAuthenticated = true;
                        
                        Console.WriteLine($"💼 Wallet Address: {walletAddress}");
                        Console.WriteLine($"💰 Current Balance: {walletBalance:F2} coins");
                        Console.WriteLine($"👤 Welcome back, {username}!");
                        
                        // Request current hash to start mining
                        await RequestCurrentHash();
                    }
                    else if (expectedType == "register_response")
                    {
                        string newWalletAddress = data.GetProperty("wallet_address").GetString();
                        Console.WriteLine($"🎉 Account created successfully!");
                        Console.WriteLine($"💼 Your new wallet address: {newWalletAddress}");
                        Console.WriteLine("💡 Please login with your new credentials to start mining.");
                    }
                }
                else
                {
                    Console.WriteLine($"❌ {message}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error processing authentication: {ex.Message}");
        }
    }
    
    private async Task RequestCurrentHash()
    {
        var hashRequest = new
        {
            type = "get_current_hash",
            session_id = sessionId
        };
        
        await writer.WriteLineAsync(JsonSerializer.Serialize(hashRequest));
    }
    
    private string ReadPasswordFromConsole()
    {
        StringBuilder password = new StringBuilder();
        ConsoleKeyInfo key;
        
        do
        {
            key = Console.ReadKey(true);
            
            if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
            {
                password.Append(key.KeyChar);
                Console.Write("*");
            }
            else if (key.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                password.Remove(password.Length - 1, 1);
                Console.Write("\b \b");
            }
        }
        while (key.Key != ConsoleKey.Enter);
        
        Console.WriteLine();
        return password.ToString();
    }
    
    private async Task ListenForMessages()
    {
        try
        {
            while (isConnected && client.Connected && isAuthenticated)
            {
                string message = await reader.ReadLineAsync();
                if (message != null)
                {
                    await ProcessServerMessage(message);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Listen error: {ex.Message}");
            isConnected = false;
            isAuthenticated = false;
        }
        finally
        {
            StopMining();
            client?.Close();
        }
    }
    
    private async Task ProcessServerMessage(string jsonMessage)
    {
        try
        {
            using JsonDocument doc = JsonDocument.Parse(jsonMessage);
            JsonElement root = doc.RootElement;
            
            string messageType = root.GetProperty("type").GetString();
            
            switch (messageType)
            {
                case "current_hash":
                case "new_hash":
                    await HandleNewHash(root.GetProperty("data"));
                    break;
                    
                case "solution_accepted":
                    await HandleSolutionAccepted(root.GetProperty("data"));
                    break;
                    
                case "mining_success":
                    HandleMiningSuccess(root.GetProperty("data"));
                    break;
                    
                case "wallet_info":
                    HandleWalletInfo(root.GetProperty("data"));
                    break;
                    
                case "error":
                    Console.WriteLine($"❌ Server error: {root.GetProperty("data").GetProperty("message").GetString()}");
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Message processing error: {ex.Message}");
        }
    }
    
    private async Task HandleNewHash(JsonElement message)
    {
        string newHash = message.GetProperty("hash").GetString();
        string targetString = message.GetProperty("target_string").GetString();
        int targetLength = message.GetProperty("target_length").GetInt32();
        double reward = message.GetProperty("mining_reward").GetDouble();
        
        // Always stop current mining first
        StopMining();
        
        // Update hash information
        currentHash = newHash;
        currentTarget = targetString;
        hashLength = targetLength;
        miningReward = reward;
        
        // Verify the server's hash calculation
        using var sha256 = SHA256.Create();
        byte[] targetBytes = Encoding.UTF8.GetBytes(targetString);
        byte[] verifyHash = sha256.ComputeHash(targetBytes);
        string verifyHashString = Convert.ToHexString(verifyHash).ToLower();
        
        Console.WriteLine($"\n🎯 New mining target received:");
        Console.WriteLine($"   💎 Target: '{targetString}' (length: {targetLength})");
        Console.WriteLine($"   🔑 Hash: {newHash}");
        Console.WriteLine($"   💰 Reward: {miningReward} coins");
        Console.WriteLine($"   ✅ Verified: {(verifyHashString == newHash ? "YES" : "NO")}");
        
        if (verifyHashString != newHash)
        {
            Console.WriteLine("⚠️  WARNING: Hash verification failed!");
        }
        
        // Reset attempt counter
        Interlocked.Exchange(ref totalAttempts, 0);
        
        Console.WriteLine($"\n🔥 UNLEASHING {threadCount} MINING THREADS!");
        Console.WriteLine($"👤 Mining as: {username} ({walletAddress})");
        
        // Wait a moment to ensure mining is fully stopped, then start new mining
        await Task.Delay(100);
        await StartMining();
    }
    
    private async Task HandleSolutionAccepted(JsonElement message)
    {
        string solverUsername = message.GetProperty("solver_username").GetString();
        string solverWallet = message.GetProperty("solver_wallet").GetString();
        string solution = message.GetProperty("solution").GetString();
        long attempts = message.GetProperty("attempts").GetInt64();
        double rewardAmount = message.GetProperty("reward_amount").GetDouble();
        string newHash = message.GetProperty("new_hash").GetString();
        string newTargetString = message.GetProperty("new_target_string").GetString();
        int targetLength = message.GetProperty("target_length").GetInt32();
        
        long myAttempts = Interlocked.Read(ref totalAttempts);
        
        // Always stop current mining immediately
        StopMining();
        
        if (solverUsername == username)
        {
            Console.WriteLine($"\n🎉🏆 YOU FOUND THE SOLUTION! 🏆🎉");
        }
        else
        {
            Console.WriteLine($"\n🎉 HASH CONQUERED!");
            Console.WriteLine($"   🏆 Champion: {solverUsername}");
            Console.WriteLine($"   💼 Wallet: {solverWallet}");
        }
        
        Console.WriteLine($"   🔑 Solution: {solution}");
        Console.WriteLine($"   ⚡ Their attempts: {attempts:N0}");
        Console.WriteLine($"   💥 Your attempts: {myAttempts:N0}");
        Console.WriteLine($"   💰 Reward: {rewardAmount} coins");
        
        // Update to new hash information immediately
        currentHash = newHash;
        currentTarget = newTargetString;
        hashLength = targetLength;
        miningReward = rewardAmount; // Keep the same reward amount
        
        // Reset attempt counter
        Interlocked.Exchange(ref totalAttempts, 0);
        
        Console.WriteLine($"\n🎯 Next target: '{newTargetString}' (length: {targetLength})");
        Console.WriteLine($"🔥 RESTARTING MINING WITH NEW HASH!");
        
        // Wait a moment to ensure everything is reset, then start mining the new hash
        await Task.Delay(200);
        await StartMining();
    }
    
    private void HandleMiningSuccess(JsonElement message)
    {
        double reward = message.GetProperty("reward").GetDouble();
        double newBalance = message.GetProperty("new_balance").GetDouble();
        string successMessage = message.GetProperty("message").GetString();
        
        walletBalance = newBalance;
        
        Console.WriteLine($"\n💎💰 MINING SUCCESS! 💰💎");
        Console.WriteLine($"   🎉 {successMessage}");
        Console.WriteLine($"   💰 Reward earned: +{reward} coins");
        Console.WriteLine($"   💼 New balance: {newBalance:F2} coins");
        Console.WriteLine($"   📈 Wallet updated!");
        
        // Play a victory sound if possible
        try
        {
            Console.Beep(800, 300);
            Thread.Sleep(100);
            Console.Beep(1000, 300);
            Thread.Sleep(100);
            Console.Beep(1200, 500);
        }
        catch { } // Ignore if beep not supported
    }
    
    private void HandleWalletInfo(JsonElement walletData)
    {
        string walletUsername = walletData.GetProperty("username").GetString();
        string address = walletData.GetProperty("wallet_address").GetString();
        double balance = walletData.GetProperty("balance").GetDouble();
        string createdAt = walletData.GetProperty("created_at").GetString();
        string lastLogin = walletData.GetProperty("last_login").GetString();
        
        Console.WriteLine($"\n💼 WALLET INFORMATION");
        Console.WriteLine($"════════════════════════════════════════");
        Console.WriteLine($"👤 Username: {walletUsername}");
        Console.WriteLine($"📍 Address: {address}");
        Console.WriteLine($"💰 Balance: {balance:F2} coins");
        Console.WriteLine($"📅 Created: {createdAt}");
        Console.WriteLine($"🔐 Last Login: {lastLogin}");
        
        var transactions = walletData.GetProperty("recent_transactions").EnumerateArray();
        Console.WriteLine($"\n📊 RECENT TRANSACTIONS:");
        Console.WriteLine($"─────────────────────────────────────────");
        
        int count = 0;
        foreach (var tx in transactions)
        {
            if (count >= 5) break; // Show only 5 most recent
            
            string txType = tx.GetProperty("type").GetString();
            double amount = tx.GetProperty("amount").GetDouble();
            string timestamp = tx.GetProperty("timestamp").GetString();
            string description = tx.GetProperty("description").GetString();
            
            Console.WriteLine($"💎 +{amount:F2} coins - {description}");
            Console.WriteLine($"   ⏰ {timestamp}");
            Console.WriteLine();
            count++;
        }
        
        if (count == 0)
        {
            Console.WriteLine("   No transactions yet. Start mining to earn coins!");
        }
    }
    
    private async Task StartMining()
    {
        // Thread-safe check to prevent multiple mining sessions
        lock (lockObject)
        {
            if (isMining || string.IsNullOrEmpty(currentHash) || !isAuthenticated)
                return;
            
            isMining = true;
        }
        
        miningCancellation = new CancellationTokenSource();
        
        Console.WriteLine($"🚀 Starting mining for hash: {currentHash}");
        Console.WriteLine($"🎯 Target string: '{currentTarget}'");
        
        // Start performance monitoring
        _ = Task.Run(() => MonitorPerformance(miningCancellation.Token));
        
        // Launch multiple mining threads for maximum CPU usage
        Task[] miningTasks = new Task[threadCount];
        for (int i = 0; i < threadCount; i++)
        {
            int threadId = i;
            miningTasks[i] = Task.Run(() => MineHashOptimized(threadId, miningCancellation.Token));
        }
        
        // Wait for any thread to find solution or cancellation
        await Task.WhenAny(miningTasks);
    }
    
    private void StopMining()
    {
        lock (lockObject)
        {
            if (!isMining) return;
            
            isMining = false;
            miningCancellation?.Cancel();
        }
        
        Console.WriteLine("⏹️  Mining stopped.");
    }
    
    private async Task MineHashOptimized(int threadId, CancellationToken cancellationToken)
    {
        var random = threadLocalRandom.Value;
        var sb = threadLocalStringBuilder.Value;
        var sha256 = threadLocalSHA256.Value;
        
        long localAttempts = 0;
        const int batchSize = 10000;
        
        // Store the hash we're mining for to detect changes
        string miningForHash = currentHash;
        
        try
        {
            while (isMining && !cancellationToken.IsCancellationRequested && isAuthenticated)
            {
                // Check if hash changed during mining
                if (miningForHash != currentHash)
                {
                    Console.WriteLine($"🔄 Thread {threadId}: Hash changed during mining. Stopping.");
                    break;
                }
                
                for (int batch = 0; batch < batchSize && isMining && miningForHash == currentHash; batch++)
                {
                    // Generate random string efficiently
                    sb.Clear();
                    for (int i = 0; i < hashLength; i++)
                    {
                        sb.Append(chars[random.Next(chars.Length)]);
                    }
                    string guess = sb.ToString();
                    
                    // Calculate hash
                    byte[] guessBytes = Encoding.UTF8.GetBytes(guess);
                    byte[] hashResult = sha256.ComputeHash(guessBytes);
                    string guessHash = Convert.ToHexString(hashResult).ToLower();
                    
                    localAttempts++;
                    
                    // Check if we found the solution (and we're still mining the right hash)
                    if (string.Equals(guessHash, miningForHash, StringComparison.OrdinalIgnoreCase) && miningForHash == currentHash)
                    {
                        long finalAttempts = Interlocked.Add(ref totalAttempts, localAttempts);
                        
                        Console.WriteLine($"\n🎉💥 SOLUTION FOUND BY THREAD {threadId}! 💥🎉");
                        Console.WriteLine($"   🔑 Solution: {guess}");
                        Console.WriteLine($"   ⚡ Total attempts: {finalAttempts:N0}");
                        Console.WriteLine($"   🧵 Thread {threadId} attempts: {localAttempts:N0}");
                        Console.WriteLine($"   👤 Mining as: {username}");
                        
                        await ReportSolution(guess, finalAttempts);
                        return;
                    }
                }
                
                // Update global counter
                Interlocked.Add(ref totalAttempts, localAttempts);
                localAttempts = 0;
                
                // Minimal delay for thread 0
                if (threadId == 0)
                {
                    await Task.Yield();
                }
            }
        }
        catch (OperationCanceledException)
        {
            Interlocked.Add(ref totalAttempts, localAttempts);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Thread {threadId} mining error: {ex.Message}");
        }
    }
    
    private async Task MonitorPerformance(CancellationToken cancellationToken)
    {
        long lastAttempts = 0;
        DateTime lastTime = DateTime.UtcNow;
        DateTime startTime = DateTime.UtcNow;
        
        try
        {
            while (!cancellationToken.IsCancellationRequested && isAuthenticated)
            {
                await Task.Delay(3000, cancellationToken);
                
                long currentAttempts = Interlocked.Read(ref totalAttempts);
                DateTime currentTime = DateTime.UtcNow;
                
                double elapsedSeconds = (currentTime - lastTime).TotalSeconds;
                double totalElapsedSeconds = (currentTime - startTime).TotalSeconds;
                long attemptsDelta = currentAttempts - lastAttempts;
                double currentHashRate = attemptsDelta / elapsedSeconds;
                double avgHashRate = currentAttempts / totalElapsedSeconds;
                
                double searchSpace = Math.Pow(chars.Length, hashLength);
                double progressPercent = (currentAttempts / searchSpace) * 100;
                double remainingHashes = searchSpace - currentAttempts;
                double etaSeconds = remainingHashes / Math.Max(currentHashRate, 1);
                TimeSpan eta = TimeSpan.FromSeconds(etaSeconds);
                
                Console.WriteLine($"⛏️  {username} | Total: {currentAttempts:N0} | Current: {currentHashRate:F0} H/s | Avg: {avgHashRate:F0} H/s");
                Console.WriteLine($"💼 Balance: {walletBalance:F2} coins | Progress: {progressPercent:F6}% | ETA: {eta:hh\\:mm\\:ss}");
                Console.WriteLine($"🎯 Mining {hashLength}-char | Reward: {miningReward} coins | Threads: {threadCount}");
                Console.WriteLine($"🔑 Current Hash: {currentHash}");
                Console.WriteLine("─────────────────────────────────────────────────────────");
                
                lastAttempts = currentAttempts;
                lastTime = currentTime;
            }
        }
        catch (OperationCanceledException) { }
    }
    
    private async Task ReportSolution(string solution, long attempts)
    {
        try
        {
            var message = new
            {
                type = "solution_found",
                session_id = sessionId,
                solution = solution,
                attempts = attempts,
                timestamp = DateTime.UtcNow.ToString("O")
            };
            
            string json = JsonSerializer.Serialize(message);
            await writer.WriteLineAsync(json);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Failed to report solution: {ex.Message}");
        }
    }
    
    // Cleanup resources
    ~CryptoMinerWithWallet()
    {
        threadLocalRandom?.Dispose();
        threadLocalStringBuilder?.Dispose();
        threadLocalSHA256?.Dispose();
    }
}

public class Program
{
    public static async Task Main(string[] args)
    {
        Console.WriteLine("💥🔥 CRYPTO MINER WITH WALLET SYSTEM 🔥💥");
        Console.WriteLine($"💪 CPU Cores Available: {Environment.ProcessorCount}");
        Console.WriteLine("💼 Wallet Authentication Required");
        Console.WriteLine();
        
        // Get server details
        Console.Write("Enter server IP (default: localhost): ");
        string serverIp = Console.ReadLine();
        if (string.IsNullOrWhiteSpace(serverIp))
            serverIp = "localhost";
            
        Console.Write("Enter server port (default: 598): ");
        string portInput = Console.ReadLine();
        int port = 598;
        if (!string.IsNullOrWhiteSpace(portInput))
            int.TryParse(portInput, out port);
        
        Console.WriteLine();
        Console.WriteLine("🚨 This will use ALL CPU cores at maximum capacity!");
        Console.WriteLine("💡 Press Ctrl+C to stop mining");
        Console.WriteLine("🔐 You'll need to login/register to start earning coins");
        Console.WriteLine();
        
        // Set process priority to high for maximum performance
        try
        {
            System.Diagnostics.Process.GetCurrentProcess().PriorityClass = 
                System.Diagnostics.ProcessPriorityClass.High;
            Console.WriteLine("⚡ Process priority set to HIGH");
        }
        catch
        {
            Console.WriteLine("⚠️  Could not set high priority (run as admin for better performance)");
        }
        
        CryptoMinerWithWallet miner = new CryptoMinerWithWallet(serverIp, port);
        
        // Handle Ctrl+C gracefully
        Console.CancelKeyPress += (sender, e) =>
        {
            e.Cancel = true;
            Console.WriteLine("\n💥 Shutting down miner with wallet...");
            Environment.Exit(0);
        };
        
        await miner.StartAsync();
    }
}