import React, { useMemo } from 'react';
import { Card } from 'antd';
import ReactECharts from 'echarts-for-react';
import { useStatsHistory } from '../hooks/useStats';
import dayjs from 'dayjs';

const COLORS = {
  SYN: '#f5222d',
  UDP: '#fa8c16',
  ICMP: '#fadb14',
  DNS_Amp: '#722ed1',
  NTP_Amp: '#2f54eb',
  ACK: '#eb2f96',
  ACL: '#9254de',
  RateLimit: '#597ef7',
  Fragment: '#a0d911',
};

const ProtocolBreakdown: React.FC = () => {
  const history = useStatsHistory();

  const option = useMemo(() => {
    const times = history.map((s) => dayjs(s.timestampNs / 1e6).format('HH:mm:ss'));

    const series = [
      { name: 'SYN Flood', key: 'synFloodDropped' as const, color: COLORS.SYN },
      { name: 'UDP Flood', key: 'udpFloodDropped' as const, color: COLORS.UDP },
      { name: 'DNS Amp', key: 'dnsAmpDropped' as const, color: COLORS.DNS_Amp },
      { name: 'NTP Amp', key: 'ntpAmpDropped' as const, color: COLORS.NTP_Amp },
      { name: 'ICMP', key: 'icmpFloodDropped' as const, color: COLORS.ICMP },
      { name: 'ACK', key: 'ackFloodDropped' as const, color: COLORS.ACK },
      { name: 'Rate Limited', key: 'rateLimited' as const, color: COLORS.RateLimit },
    ];

    return {
      tooltip: {
        trigger: 'axis' as const,
        axisPointer: { type: 'cross' as const },
        backgroundColor: '#1f1f1f',
        borderColor: '#424242',
        textStyle: { color: '#fff', fontSize: 11 },
      },
      legend: {
        data: series.map((s) => s.name),
        textStyle: { color: 'rgba(255,255,255,0.55)', fontSize: 10 },
        top: 0,
        type: 'scroll' as const,
        itemWidth: 12,
        itemHeight: 8,
      },
      grid: { left: 50, right: 15, top: 35, bottom: 25 },
      xAxis: {
        type: 'category' as const,
        data: times,
        axisLabel: { color: 'rgba(255,255,255,0.35)', fontSize: 10 },
        axisLine: { lineStyle: { color: '#303030' } },
      },
      yAxis: {
        type: 'value' as const,
        axisLabel: {
          color: 'rgba(255,255,255,0.35)',
          fontSize: 10,
          formatter: (v: number) => v >= 1e6 ? `${(v / 1e6).toFixed(0)}M` : v >= 1e3 ? `${(v / 1e3).toFixed(0)}K` : String(v),
        },
        splitLine: { lineStyle: { color: '#252525' } },
      },
      series: series.map((s) => ({
        name: s.name,
        type: 'bar',
        stack: 'drops',
        data: history.map((h) => h[s.key]),
        itemStyle: { color: s.color },
        emphasis: { focus: 'series' as const },
        barMaxWidth: 12,
      })),
    };
  }, [history]);

  return (
    <Card title="Drop Breakdown (Stacked)" size="small">
      <ReactECharts option={option} style={{ height: 250 }} opts={{ renderer: 'canvas' }} />
    </Card>
  );
};

export default ProtocolBreakdown;
