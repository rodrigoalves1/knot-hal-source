/*
* Copyright (c) 2015, CESAR.
* All rights reserved.
*
* This software may be modified and distributed under the terms
* of the BSD license. See the LICENSE file for details.
*
*/
#include "nrf24l01.h"
#include "spi.h"

// Alias for spi_transfer function of the SPI module
#define rf_io		spi_transfer

// Pipes addresses base
#define	PIPE0_ADDR_BASE	0x55aa55aa5aLL
#define	PIPE1_ADDR_BASE	0xaa55aa55a5LL

// data word size
#define DATA_SIZE	sizeof(byte_t)

// time delay in microseconds (us)
#define TPD2STBY			5000		//5ms
#define THCE					10			//10us
#define TPECE2CSN		4				//4us
#define TSTBY2A			130			//130us

// *************heartbeat*************

typedef struct {
	uint8_t	enaa,
					en_rxaddr,
					rx_addr,
					rx_pw;
} pipe_reg_t;

static const pipe_reg_t pipe_reg[] PROGMEM = {
	{ AA_P0, RXADDR_P0, RX_ADDR_P0, RX_PW_P0 },
	{ AA_P1, RXADDR_P1, RX_ADDR_P1, RX_PW_P1 },
	{ AA_P2, RXADDR_P2, RX_ADDR_P2, RX_PW_P2 },
	{ AA_P3, RXADDR_P3, RX_ADDR_P3, RX_PW_P3 },
	{ AA_P4, RXADDR_P4, RX_ADDR_P4, RX_PW_P4 },
	{ AA_P5, RXADDR_P5, RX_ADDR_P5, RX_PW_P5 }
};

typedef enum {
	UNKNOWN_MODE,
	POWER_DOWN_MODE,
	STANDBY_I_MODE,
	RX_MODE,
	TX_MODE,
	STANDBY_II_MODE,
} en_modes_t ;

static en_modes_t m_mode = UNKNOWN_MODE;

#ifdef ARDUINO
#include <Arduino.h>

#define CE	1

#define DELAY_US(us)		delayMicroseconds(us)
#define DELAY_MS(ms)	delay(ms)

/* ----------------------------------
 * Local operation functions
 */

static inline void enable(void)
{
	PORTB |= (1 << CE);
}

static inline void disable(void)
{
	PORTB &= ~(1 << CE);
}

static inline void io_setup()
{
	// PB1 = 0 (digital PIN 9) => CE = 0
	// standby-l mode
	PORTB &= ~(1 << CE);

	// PB1 as output
	DDRB |= (1 << CE);

	disable();
	spi_init();
}

static inline void io_reset()
{
	disable();
	spi_deinit();
}

#else		// ifdef (ARDUINO)

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>

#define CE	25

#define LOW	0
#define HIGH	1

#define DELAY_US(us)		usleep(us)
#define DELAY_MS(ms)	usleep((ms)*1000)

#define BCM2709_RPI2	0x3F000000
#define BCM2708_RPI		0x20000000

#ifdef RPI2_BOARD
#define BCM2708_PERI_BASE		BCM2709_RPI2
#elif RPI_BOARD
#define BCM2708_PERI_BASE		BCM2708_RPI
#else
#error Board identifier required to BCM2708_PERI_BASE.
#endif

#define GPIO_BASE 		(BCM2708_PERI_BASE + 0x200000)
#define PAGE_SIZE		(4*1024)
#define BLOCK_SIZE		(4*1024)

//Raspberry pi GPIO Macros
#define INP_GPIO(g)					*(gpio+((g)/10)) &= ~(7<<(((g)%10)*3))
#define OUT_GPIO(g)				*(gpio+((g)/10)) |=  (1<<(((g)%10)*3))
#define SET_GPIO_ALT(g,a)	*(gpio+(((g)/10))) |= (((a)<=3?(a)+4:(a)==4?3:2)<<(((g)%10)*3))

#define GPIO_SET						*(gpio+7)  // sets   bits which are 1 ignores bits which are 0
#define GPIO_CLR						*(gpio+10) // clears bits which are 1 ignores bits which are 0

#define GET_GPIO(g)				(*(gpio+13)&(1<<g)) // 0 if LOW, (1<<g) if HIGH

#define GPIO_PULL					*(gpio+37) // Pull up/pull down
#define GPIO_PULLCLK0			*(gpio+38) // Pull up/pull down clock

static volatile unsigned				*gpio;

/* ----------------------------------
 * Local operation functions
 */

static int dump_data(void *pdata, int len)
{
    int i, off, col, n;
    unsigned char *pd = pdata;
    char buff[256];

    for (off = n = 0; off < len; off += 16) {
        n = sprintf(buff, "\t [%04x]", off);
        for (i = off, col = 16; col != 0 && i < len; --col, ++i)
            n += sprintf(buff + n, " %02lX", (ulong)pd[i]);
        // if (col != 0 && off != 0)
        for (; col != 0; --col)
            n += sprintf(buff + n, "   ");
        n += sprintf(buff + n, " - ");
        for (i = off, col = 16; col != 0 && i < len; --col, ++i)
            n += sprintf(buff + n, "%c", pd[i] >= ' ' && pd[i] < 0x7f ? pd[i] : '.');
        printf("%s\r\n", buff);
    }
    return 0;
}

static inline void enable(void)
{
	GPIO_SET = (1<<CE);
}

static inline void disable(void)
{
	GPIO_CLR = (1<<CE);
}

static void io_setup()
{
	//open /dev/mem
	int mem_fd = open("/dev/mem", O_RDWR|O_SYNC);
	if (mem_fd < 0) {
		printf("can't open /dev/mem \n");
		exit(-1);
	}

	gpio = (volatile unsigned*)mmap(NULL,
																BLOCK_SIZE,
																PROT_READ | PROT_WRITE,
																MAP_SHARED,
																mem_fd,
																GPIO_BASE);
   	close(mem_fd);
   	if (gpio == MAP_FAILED) {
      		printf("mmap error\n");
      		exit(-1);
   	}

	GPIO_CLR = (1<<CE);
	INP_GPIO(CE);
	OUT_GPIO(CE);

	disable();
	spi_init();
}

static void io_reset()
{
	disable();
	munmap((void*)gpio, BLOCK_SIZE);
	spi_deinit();
}

#endif		// ifdef (ARDUINO)

static inline result_t inr(byte_t reg)
{
	byte_t value = NOP;
	reg = R_REGISTER(reg);
	rf_io(&reg, DATA_SIZE, &value, DATA_SIZE);
	return (result_t)value;
}

static inline void inr_data(byte_t reg, pdata_t pd, len_t len)
{
	memset(pd, NOP, len);
	reg = R_REGISTER(reg);
	rf_io(&reg, DATA_SIZE, pd, len);
}

static inline void outr(byte_t reg, byte_t value)
{
	reg = W_REGISTER(reg);
	rf_io(&reg, DATA_SIZE, &value, DATA_SIZE);
}

static inline void outr_data(byte_t reg, pdata_t pd, len_t len)
{
	reg = W_REGISTER(reg);
	rf_io(&reg, DATA_SIZE, pd, len);
}

static inline result_t command(byte_t cmd)
{
	rf_io(NULL, 0, &cmd, DATA_SIZE);
	// return device status register
	return (result_t)cmd;
}

static inline result_t command_data(byte_t cmd, pdata_t pd, len_t len)
{
	rf_io(&cmd, DATA_SIZE, pd, len);
	// return device status register
	return command(NOP);
}

static void set_address_pipe(byte_t reg, byte_t pipe)
{
	uint64_t	pipe_addr = (pipe == 0) ? PIPE0_ADDR_BASE : PIPE1_ADDR_BASE;

	pipe_addr += (pipe << 4) + pipe;
	outr_data(reg, &pipe_addr, (reg == TX_ADDR || pipe < 2) ? AW_RD(inr(SETUP_AW)) : DATA_SIZE);
}

static result_t set_standby1(byte_t pipe)
{
	if (m_mode == UNKNOWN_MODE) {
		return ERROR;
	}

	disable();
	// set CFG_PRIM_RX=0 (PTX) that should use only 22uA of power
	byte_t config = inr(CONFIG) & ~CFG_PRIM_RX;
	outr(CONFIG, config | CFG_PWR_UP);
	if (m_mode == POWER_DOWN_MODE) {
		// delay time to Tpd2stby timing
		DELAY_US(TPD2STBY);
	}
	m_mode = STANDBY_I_MODE;
	set_address_pipe(RX_ADDR_P0, pipe);
	return SUCCESS;
}

/*	-----------------------------------
 * Public operation functions
 */
//>>>>>>>>>>
// TODO: functions to test, we can remove them on development end
result_t nrf24l01_inr(byte_t reg)
{
	return inr(reg);
}

void nrf24l01_inr_data(byte_t reg, pdata_t pd, len_t len)
{
	inr_data(reg, pd, len);
}

void nrf24l01_outr(byte_t reg, byte_t value)
{
	outr(reg, value);
}

void nrf24l01_outr_data(byte_t reg, pdata_t pd, len_t len)
{
	outr_data(reg, pd, len);
}

result_t nrf24l01_command(byte_t cmd)
{
	return command(cmd);
}

result_t nrf24l01_ce_on(void)
{
	enable();
}

result_t nrf24l01_ce_off(void)
{
	disable();
}

void nrf24l01_set_address_pipe(byte_t reg, byte_t pipe)
{
	set_address_pipe(reg, pipe);
}
//<<<<<<<<<<

result_t nrf24l01_deinit(void)
{
	int_t		value;

	if (m_mode == UNKNOWN_MODE) {
		return SUCCESS;
	}

	disable();
	outr(CONFIG, inr(CONFIG) & ~CFG_PWR_UP);
	m_mode = UNKNOWN_MODE;

	io_reset();
	return SUCCESS;
}

result_t	nrf24l01_init(void)
{
	byte_t		value;

	if (m_mode != UNKNOWN_MODE) {
		return SUCCESS;
	}

	io_setup();

	// set device in power down mode
	outr(CONFIG, inr(CONFIG) & ~CFG_PWR_UP);
	// Delay to establish to operational timing of the nRF24L01
	DELAY_US(TPD2STBY);

	// set PTX mode and CRC 16-bit
	value = inr(CONFIG) & ~CONFIG_MASK;
	outr(CONFIG, value | CFG_EN_CRC | CFG_CRCO);

	// reset channel and TX observe registers
	outr(RF_CH, inr(RF_CH) & ~RF_CH_MASK);
	// Set the device channel
	outr(RF_CH, CH(NRF24L01_CHANNEL_DEFAULT));

	// set RF speed and output power
	value = inr(RF_SETUP) & ~RF_SETUP_MASK;
	outr(RF_SETUP, value | RF_DR(NRF24L01_DATA_RATE) | RF_PWR(NRF24L01_POWER));

	// set address widths
	value = inr(SETUP_AW) & ~SETUP_AW_MASK;
	outr(SETUP_AW, value | AW(NRF24L01_ADDR_WIDTHS));

	// disable Auto Retransmit Count
	outr(SETUP_RETR, RETR_ARC(ARC_DISABLE));

	// disable all Auto Acknowledgment of pipes
	outr(EN_AA, inr(EN_AA) & ~EN_AA_MASK);

	// disable all RX addresses
	outr(EN_RXADDR, inr(EN_RXADDR) & ~EN_RXADDR_MASK);

	// enable dynamic payload to all pipes
	outr(FEATURE, (inr(FEATURE) & ~FEATURE_MASK) | FT_EN_DPL | FT_EN_ACK_PAY | FT_EN_DYN_ACK);
	value = inr(DYNPD) & ~DYNPD_MASK;
	outr(DYNPD, value | (DPL_P5 | DPL_P4 | DPL_P3 | DPL_P2 | DPL_P1 | DPL_P0));

	// reset all the FIFOs
	command(FLUSH_TX);
	command(FLUSH_RX);

	// reset pending status
	value = inr(STATUS) & ~STATUS_MASK;
	outr(STATUS, value | ST_RX_DR | ST_TX_DS | ST_MAX_RT);

	m_mode = POWER_DOWN_MODE;

	// set device to standby-I mode
	set_standby1(0);

	return SUCCESS;
}

result_t nrf24l01_set_channel(byte_t ch)
{
	byte_t max;

	if (m_mode == UNKNOWN_MODE) {
		return ERROR;
	}

	max = RF_DR(inr(RF_SETUP)) == DR_2MBPS ? CH_MAX_2MBPS : CH_MAX_1MBPS;
	if (ch != _CONSTRAIN(ch, CH_MIN, max))
		return ERROR;

	if (ch != CH(inr(RF_CH))) {
		set_standby1(0);
		outr(STATUS, ST_RX_DR | ST_TX_DS | ST_MAX_RT);
		command(FLUSH_TX);
		command(FLUSH_RX);
		// Set the device channel
		outr(RF_CH, CH(_CONSTRAIN(ch, CH_MIN, max)));
	}
	return SUCCESS;
}

result_t nrf24l01_get_channel(void)
{
	if (m_mode == UNKNOWN_MODE) {
		return ERROR;
	}

	return CH(inr(RF_CH));
}

result_t nrf24l01_open_pipe(byte_t pipe)
{
	pipe_reg_t rpipe;

	if (m_mode == UNKNOWN_MODE || pipe > NRF24L01_PIPE_MAX) {
		return ERROR;
	}

	memcpy_P(&rpipe, &pipe_reg[pipe], sizeof(pipe_reg_t));

	if (!(inr(EN_RXADDR) & rpipe.en_rxaddr)) {
		set_address_pipe(rpipe.rx_addr, pipe);
		outr(EN_RXADDR, inr(EN_RXADDR) | rpipe.en_rxaddr);
		outr(EN_AA, inr(EN_AA) | rpipe.enaa);
	}
	return SUCCESS;
}

result_t nrf24l01_close_pipe(byte_t pipe)
{
	pipe_reg_t rpipe;

	if (m_mode == UNKNOWN_MODE || pipe > NRF24L01_PIPE_MAX) {
		return ERROR;
	}

	memcpy_P(&rpipe, &pipe_reg[pipe], sizeof(pipe_reg_t));

	if (inr(EN_RXADDR) & rpipe.en_rxaddr) {
		outr(EN_RXADDR, inr(EN_RXADDR) & ~rpipe.en_rxaddr);
		outr(EN_AA, inr(EN_AA) & ~rpipe.enaa);
		outr(SETUP_RETR, RETR_ARC(ARC_DISABLE));
	}
	return SUCCESS;
}

result_t nrf24l01_set_standby(void)
{
	if (m_mode == UNKNOWN_MODE) {
		return ERROR;
	}

	set_standby1(0);
	return command(NOP);
}

result_t nrf24l01_set_prx(void)
{
	if (m_mode == UNKNOWN_MODE) {
		return ERROR;
	}

	set_standby1(0);
	outr(CONFIG, inr(CONFIG) | CFG_PRIM_RX);
	m_mode = RX_MODE;
	enable();
	// delay time to Tstdby2a timing
	DELAY_US(TSTBY2A);
	return command(NOP);
}

result_t nrf24l01_prx_pipe_available(void)
{
	byte_t pipe = NRF24L01_NO_PIPE;

	if (!(inr(FIFO_STATUS) & FIFO_RX_EMPTY)) {
		pipe = ST_RX_P_NO(inr(STATUS));
		if (pipe > NRF24L01_PIPE_MAX) {
			pipe = NRF24L01_NO_PIPE;
		}
	}
	return (result_t)pipe;
}

// read RX payload width for the top R_RX_PAYLOAD in the RX FIFO.
result_t nrf24l01_prx_data(pdata_t pdata, len_t len)
{
	len_t		rxlen = 0;

	if (m_mode != RX_MODE || pdata == NULL || len == 0) {
		return ERROR;
	}

	outr(STATUS, ST_RX_DR);

	command_data(R_RX_PL_WID, &rxlen, DATA_SIZE);
    // note: flush RX FIFO if the read value is larger than 32 bytes.
	if (rxlen > NRF24L01_PAYLOAD_SIZE || rxlen == 0) {
		command(FLUSH_RX);
		return ERROR;
	}

	rxlen = _MIN(len, rxlen);
	command_data(R_RX_PAYLOAD, pdata, rxlen);
	return (result_t)rxlen;
}

result_t nrf24l01_set_ptx(byte_t pipe)
{
	if (m_mode == UNKNOWN_MODE) {
		return ERROR;
	}

	set_standby1(pipe);
#if (NRF24L01_ARC != ARC_DISABLE)
	// set ARC and ARD by pipe index to different retry periods to reduce data collisions
	outr(SETUP_RETR, RETR_ARD(((pipe *2) + 5)) | RETR_ARC(NRF24L01_ARC));
#endif
	set_address_pipe(TX_ADDR, pipe);
	outr(CONFIG, inr(CONFIG) & ~CFG_PRIM_RX);
	outr(STATUS, ST_TX_DS | ST_MAX_RT);
	m_mode = TX_MODE;
	enable();
	return command(NOP);
}

result_t nrf24l01_ptx_data(pdata_t pdata, len_t len, bool ack)
{
	static uint8_t raw[NRF24L01_PAYLOAD_SIZE];

	if (m_mode != TX_MODE || pdata == NULL ||
		 len == 0 || len > NRF24L01_PAYLOAD_SIZE) {
		return ERROR;
	}

	memcpy(raw, pdata, len);
	return command_data(!ack ? W_TX_PAYLOAD_NOACK : W_TX_PAYLOAD, raw, len);
}

result_t nrf24l01_ptx_wait_datasent(void)
{
	if (m_mode != TX_MODE) {
		return ERROR;
	}

	while(!(inr(FIFO_STATUS) & FIFO_TX_EMPTY)) {
		asm("nop");
		asm("nop");
		if (inr(STATUS & ST_MAX_RT)) {
			outr(STATUS, ST_MAX_RT);
			command(FLUSH_TX);
			return ERROR;
		}
	}

	return SUCCESS;
}

result_t nrf24l01_ptx_isempty(void)
{
	if (m_mode != TX_MODE) {
		return true;
	}

	return((inr(FIFO_STATUS) & FIFO_TX_EMPTY) != 0);
}

result_t nrf24l01_ptx_isfull(void)
{
	if (m_mode != TX_MODE) {
		return false;
	}

	return((inr(FIFO_STATUS) & FIFO_TX_FULL) != 0);
}
