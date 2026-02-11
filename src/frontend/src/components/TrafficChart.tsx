import React, { useMemo } from 'react';
import { Card } from 'antd';
import ReactECharts from 'echarts-for-react';
import { useStatsHistory } from '../hooks/useStats';
import { TRAFFIC_COLORS } from '../styles/theme';
import dayjs from 'dayjs';

interface Props {
  mode: 'pps' | 'bps';
}

const TrafficChart: React.FC<Props> = ({ mode }) => {
  const history = useStatsHistory();

  const option = useMemo(() => {
    const times = history.map((s) =>
      dayjs(s.timestampNs / 1e6).format('HH:mm:ss'),
    );

    const isPPS = mode === 'pps';
    const title = isPPS ? 'Traffic (PPS)' : 'Traffic (BPS)';

    const rxData = history.map((s) => (isPPS ? s.rxPps : s.rxBps));
    const txData = history.map((s) => (isPPS ? s.txPps : s.txBps));
    const dropData = history.map((s) => (isPPS ? s.dropPps : s.dropBps));

    return {
      title: { text: title, textStyle: { color: '#fff', fontSize: 14 } },
      tooltip: {
        trigger: 'axis' as const,
        backgroundColor: '#1f1f1f',
        borderColor: '#424242',
        textStyle: { color: '#fff' },
      },
      legend: {
        data: ['Inbound', 'Passed', 'Dropped'],
        textStyle: { color: 'rgba(255,255,255,0.65)' },
        top: 0,
        right: 0,
      },
      grid: { left: 60, right: 20, top: 40, bottom: 30 },
      xAxis: {
        type: 'category' as const,
        data: times,
        axisLabel: { color: 'rgba(255,255,255,0.45)' },
        axisLine: { lineStyle: { color: '#424242' } },
      },
      yAxis: {
        type: 'value' as const,
        axisLabel: {
          color: 'rgba(255,255,255,0.45)',
          formatter: (v: number) => {
            if (v >= 1e9) return `${(v / 1e9).toFixed(1)}G`;
            if (v >= 1e6) return `${(v / 1e6).toFixed(1)}M`;
            if (v >= 1e3) return `${(v / 1e3).toFixed(1)}K`;
            return String(v);
          },
        },
        splitLine: { lineStyle: { color: '#303030' } },
      },
      series: [
        {
          name: 'Inbound',
          type: 'line',
          data: rxData,
          smooth: true,
          showSymbol: false,
          lineStyle: { width: 2 },
          areaStyle: { opacity: 0.1 },
          color: TRAFFIC_COLORS.rx,
        },
        {
          name: 'Passed',
          type: 'line',
          data: txData,
          smooth: true,
          showSymbol: false,
          lineStyle: { width: 2 },
          areaStyle: { opacity: 0.1 },
          color: TRAFFIC_COLORS.tx,
        },
        {
          name: 'Dropped',
          type: 'line',
          data: dropData,
          smooth: true,
          showSymbol: false,
          lineStyle: { width: 2 },
          areaStyle: { opacity: 0.15 },
          color: TRAFFIC_COLORS.drop,
        },
      ],
    };
  }, [history, mode]);

  return (
    <Card size="small">
      <ReactECharts
        option={option}
        style={{ height: 280 }}
        opts={{ renderer: 'canvas' }}
      />
    </Card>
  );
};

export default TrafficChart;
