#pragma once

class StringBuf
{
public:
	StringBuf(uint32 bufferSize)
	{
		this->str = (uint8*)malloc(bufferSize + 4);
		if (!this->str)
		{
			// Fallback to smaller allocation
			bufferSize = std::min(bufferSize, (uint32)(1024 * 1024));
			this->str = (uint8*)malloc(bufferSize + 4);
		}
		this->allocated = true;
		this->length = 0;
		this->limit = this->str ? bufferSize : 0;
	}

	~StringBuf()
	{
		if (this->allocated)
			free(this->str);
	}

	template<typename TFmt, typename ... TArgs>
	void addFmt(const TFmt& format, TArgs&&... args)
	{
		if (!this->str)
			return;
		size_t remaining = (this->length < this->limit) ? (size_t)(this->limit - this->length) : 0;
		auto r = fmt::vformat_to_n((char*)(this->str + this->length), remaining, fmt::detail::to_string_view(format), fmt::make_format_args(args...));
		if ((uint32)r.size > remaining)
		{
			// Buffer too small, grow and retry
			_reserve(std::max<uint32>(this->length + (uint32)r.size + 64, this->limit + this->limit / 2));
			remaining = (size_t)(this->limit - this->length);
			r = fmt::vformat_to_n((char*)(this->str + this->length), remaining, fmt::detail::to_string_view(format), fmt::make_format_args(args...));
		}
		this->length += (uint32)std::min((size_t)r.size, remaining);
	}

	void add(const char* appendedStr)
	{
		if (!this->str)
			return;
		const char* outputStart = (char*)(this->str + this->length);
		char* output = (char*)outputStart;
		const char* outputEnd = (char*)(this->str + this->limit - 1);
		while (output < outputEnd)
		{
			char c = *appendedStr;
			if (c == '\0')
				break;
			*output = c;
			appendedStr++;
			output++;
		}
		this->length += (uint32)(output - outputStart);
		*output = '\0';
	}

	void add(std::string_view appendedStr)
	{
		size_t copyLen = appendedStr.size();
		if (this->length + copyLen + 1 >= this->limit)
			_reserve(std::max<uint32>(this->length + copyLen + 64, this->limit + this->limit / 2));
		char* outputStart = (char*)(this->str + this->length);
		std::copy(appendedStr.data(), appendedStr.data() + copyLen, outputStart);
		length += copyLen;
		outputStart[copyLen] = '\0';
	}

	void reset()
	{
		length = 0;
	}

	uint32 getLen() const
	{
		return length;
	}

	const char* c_str() const
	{
		str[length] = '\0';
		return (const char*)str;
	}

	void shrink_to_fit()
	{
		if (!this->allocated)
			return;
		uint32 newLimit = this->length;
		this->str = (uint8*)realloc(this->str, newLimit + 4);
		this->limit = newLimit;
	}

private:
	void _reserve(uint32 newLimit)
	{
		cemu_assert_debug(newLimit > length);
		this->str = (uint8*)realloc(this->str, newLimit + 4);
		this->limit = newLimit;
	}

	uint8*	str;
	uint32	length; /* in bytes */
	uint32	limit; /* in bytes */
	bool	allocated;
};