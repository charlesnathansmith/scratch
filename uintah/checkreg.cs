private static bool RegCheck()
{
	try
	{
		string text = CSSimulator.AppPath + "\\CSDrillingAndWorkoverSecurityInstall.exe";
		if (File.Exists(text))
		{
			CustomActions();
			Process.Start(text);
			while (File.Exists(text))
			{
			}
		}
	}
	catch (Exception ex)
	{
		MessageBox.Show(ex.ToString());
	}
	RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\CSManfSim\\Contact\\Network\\Web");
	if (registryKey == null)
	{
		MessageBox.Show(LocalizedCodeStrings.InvalidRegistryDetectedPleaseContactCSManufacturingIfYouHaveReachedThisMessageInError, "Invalid Registry");
		return false;
	}
	PhysicalAddress physicalAddress = null;
	try
	{
		byte[] array = (byte[])registryKey.GetValue("MAC");
		for (int i = 0; i < array.Length; i++)
		{
			byte b = (byte)((uint)((array[i] & 0xF0) >> 4) ^ 9u);
			byte b2 = (byte)(((array[i] & 0xF) ^ 9) << 4);
			array[i] = (byte)(b + b2);
		}
		NetworkInterface[] allNetworkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
		foreach (NetworkInterface networkInterface in allNetworkInterfaces)
		{
			if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
			{
				physicalAddress = networkInterface.GetPhysicalAddress();
				byte[] addressBytes = physicalAddress.GetAddressBytes();
				if (array.Length != addressBytes.Length)
				{
					physicalAddress = null;
				}
				for (int k = 0; k < array.Length; k++)
				{
					if (addressBytes[k] != array[k])
					{
						physicalAddress = null;
						break;
					}
				}
			}
			if (physicalAddress != null)
			{
				break;
			}
		}
	}
	catch
	{
		MessageBox.Show(LocalizedCodeStrings.InvalidRegistryDetectedPleaseContactCSManufacturingIfYouHaveReachedThisMessageInError, LocalizedCodeStrings.InvalidRegistry);
		return false;
	}
	if (physicalAddress == null)
	{
		MessageBox.Show(LocalizedCodeStrings.InvalidRegistryDetectedPleaseContactCSManufacturingIfYouHaveReachedThisMessageInError, LocalizedCodeStrings.InvalidRegistry);
		return false;
	}
	return true;
}
