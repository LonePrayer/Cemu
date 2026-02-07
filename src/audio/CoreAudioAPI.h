#pragma once
#if defined(CEMU_IOS)

#include "IAudioAPI.h"
#import <AudioToolbox/AudioToolbox.h>

class CoreAudioAPI : public IAudioAPI
{
public:
	class CoreAudioDeviceDescription : public DeviceDescription
	{
	public:
		CoreAudioDeviceDescription(const std::wstring& name)
			: DeviceDescription(name) {}
		std::wstring GetIdentifier() const override { return L"ios_default"; }
	};

	CoreAudioAPI(uint32 samplerate, uint32 channels, uint32 samples_per_block, uint32 bits_per_sample);
	~CoreAudioAPI();

	AudioAPI GetType() const override { return Cubeb; } // reuse Cubeb enum slot

	bool NeedAdditionalBlocks() const override;
	bool FeedBlock(sint16* data) override;
	bool Play() override;
	bool Stop() override;
	void SetVolume(sint32 volume) override;

	static std::vector<DeviceDescriptionPtr> GetDevices();
	static bool InitializeStatic();

private:
	AudioComponentInstance m_audioUnit = nullptr;
	bool m_isPlaying = false;
	float m_volumeScale = 1.0f;

	mutable std::shared_mutex m_mutex;
	std::vector<uint8> m_buffer;

	static OSStatus RenderCallback(void* inRefCon, AudioUnitRenderActionFlags* ioActionFlags,
		const AudioTimeStamp* inTimeStamp, UInt32 inBusNumber, UInt32 inNumberFrames,
		AudioBufferList* ioData);
};

#endif
