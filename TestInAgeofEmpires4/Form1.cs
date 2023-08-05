using System.Diagnostics;

namespace 帝国
{
	public partial class Form1 : Form
	{
		public Form1()
		{
			InitializeComponent();
		}
		MemHelper memhelper;
		nint a;
		nint replayToggle;
		private void button1_Click(object sender, EventArgs e)
		{
			var procName = "RelicCardinal";
			while (Process.GetProcessesByName(procName).Length == 0) { System.Threading.Thread.Sleep(500); }
			var targetProcess = Process.GetProcessesByName(procName)[0];
			if (memhelper==null)
			{
				memhelper = new MemHelper(targetProcess);
			}
			
			var _tokenSource = new CancellationTokenSource();
			//Task.Run(() => ProcessDataLoop( _tokenSource.Token));
			if (replayToggle==IntPtr.Zero)
			{
				replayToggle = memhelper.GetStaticAddressFromSig("48 8B D8 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 89 5C 24 ?");
				var abcd = memhelper.GetStaticAddressFromSig("75 03 45 8A CB");
				a = memhelper.ReadIntPtr(abcd);
			}
			 
			memhelper.WriteByte(replayToggle+0xe8 , 0xf5);
			
			//75 03 45 8A CB
		  
			//var a = ReadIntPtr(0x863FE08 + memhelper.BaseAddress);
			var b = memhelper.ReadIntPtr(a);
			var c = memhelper.ReadIntPtr(b + 0x2718);


				memhelper.WriteInt32(c + 0x2C8, 0);

		}
		public byte[] olds = new byte[] { 0x41, 0x8a, 0xd3 };
		public byte[] news = new byte[] { 0xb2, 01, 0x90 };
		void ProcessDataLoop(CancellationToken token)
		{
			while (true)
			{
				Task.Delay(200, token).Wait(token); // 每隔二秒等待一次
													//48 8D 15 ? ? ? ? 48 89 54 24 ? B9 ? ? ? ? E8 ? ? ? ? 48 8B C8 48 89 44 24 ? 33 C0 48 85 C9 74 06 E8 ? ? ? ? 90 48 89 03 48 8B C3 48 83 C4 20 5B C3 40 53 48 83 EC 20 48 8B D9 E8 ? ? ? ? 48 8D 05 ? ? ? ? 41 B8 ? ? ? ?
													//EB DD 48 8B C3 EB ED CC 48 89 54 24 ?   +0x10
				var inMap = memhelper.ReadInt32(memhelper.BaseAddress + 0x85E8240);
				var change = memhelper.ReadByte(memhelper.BaseAddress + 0x570713);
				if (inMap == 2 && change != 178)
				{
					//41 8A D3 8A C2
					memhelper.WriteBytes(0x570713, news);
					var a = 1;

				}
				if (inMap == 1 && change != 65)
				{
					memhelper.WriteBytes(0x570713, olds);
				}
			}


		}


		private void button2_Click(object sender, EventArgs e)
		{
			memhelper.WriteBytes(0x570713, olds);
		}
	}
}