#include "nsyshid.h"
#include "Backend.h"
#include "BackendEmulated.h"
#if !CEMU_IOS
#include "BackendLibusb.h"
#endif

namespace nsyshid::backend
{
	void AttachDefaultBackends()
	{
		// add libusb backend
#if !CEMU_IOS
		{
			auto backendLibusb = std::make_shared<backend::libusb::BackendLibusb>();
			if (backendLibusb->IsInitialisedOk())
			{
				AttachBackend(backendLibusb);
			}
		}
#endif
	   // add emulated backend
		{
			auto backendEmulated = std::make_shared<backend::emulated::BackendEmulated>();
			if (backendEmulated->IsInitialisedOk())
			{
				AttachBackend(backendEmulated);
			}
		}
	}
} // namespace nsyshid::backend
