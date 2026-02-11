import type { ThemeConfig } from 'antd';

export const darkTheme: ThemeConfig = {
  token: {
    colorPrimary: '#1668dc',
    colorBgContainer: '#1f1f1f',
    colorBgElevated: '#262626',
    colorBgLayout: '#141414',
    colorBorder: '#424242',
    colorText: 'rgba(255, 255, 255, 0.85)',
    colorTextSecondary: 'rgba(255, 255, 255, 0.65)',
    borderRadius: 6,
    fontFamily:
      "-apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Segoe UI', Roboto, 'Helvetica Neue', monospace",
  },
  components: {
    Layout: {
      siderBg: '#1a1a2e',
      headerBg: '#1a1a2e',
      bodyBg: '#141414',
    },
    Menu: {
      darkItemBg: '#1a1a2e',
      darkItemSelectedBg: '#1668dc',
    },
    Card: {
      colorBgContainer: '#1f1f1f',
    },
    Table: {
      colorBgContainer: '#1f1f1f',
      headerBg: '#262626',
    },
    Statistic: {
      colorTextDescription: 'rgba(255, 255, 255, 0.45)',
    },
  },
};

// Chart color palette for attack types
export const ATTACK_COLORS: Record<string, string> = {
  syn_flood: '#f5222d',
  udp_flood: '#fa8c16',
  icmp_flood: '#fadb14',
  ack_flood: '#eb2f96',
  dns_amplification: '#722ed1',
  ntp_amplification: '#2f54eb',
  ssdp_amplification: '#13c2c2',
  memcached_amplification: '#52c41a',
  fragment: '#a0d911',
  rst_flood: '#ff4d4f',
  rate_limited: '#597ef7',
  acl_dropped: '#9254de',
};

// Traffic chart colors
export const TRAFFIC_COLORS = {
  rx: '#1668dc',
  tx: '#52c41a',
  drop: '#f5222d',
};
