import React, { useMemo } from 'react';
import { Card, Typography } from 'antd';
import ReactECharts from 'echarts-for-react';
import { useCurrentStats } from '../hooks/useStats';
import { isAttackActive, currentAttackType } from '../mock/generator';

const { Text } = Typography;

const ThreatGauge: React.FC = () => {
  const stats = useCurrentStats();
  const attack = isAttackActive();
  const atkType = currentAttackType();

  const threatLevel = useMemo(() => {
    if (!stats) return 0;
    const dropRatio = stats.rxPps > 0 ? stats.dropPps / stats.rxPps : 0;
    if (dropRatio > 0.5) return Math.min(dropRatio * 120, 100);
    if (dropRatio > 0.1) return dropRatio * 80;
    return dropRatio * 40;
  }, [stats]);

  const threatLabel = threatLevel > 70 ? 'CRITICAL' : threatLevel > 40 ? 'HIGH' : threatLevel > 15 ? 'MEDIUM' : 'LOW';
  const threatColor = threatLevel > 70 ? '#f5222d' : threatLevel > 40 ? '#fa8c16' : threatLevel > 15 ? '#fadb14' : '#52c41a';

  const option = useMemo(() => ({
    series: [
      {
        type: 'gauge',
        startAngle: 200,
        endAngle: -20,
        min: 0,
        max: 100,
        splitNumber: 10,
        radius: '90%',
        center: ['50%', '55%'],
        axisLine: {
          lineStyle: {
            width: 18,
            color: [
              [0.15, '#52c41a'],
              [0.4, '#fadb14'],
              [0.7, '#fa8c16'],
              [1, '#f5222d'],
            ],
          },
        },
        pointer: {
          itemStyle: { color: 'auto' },
          length: '60%',
          width: 5,
        },
        axisTick: { distance: -18, length: 6, lineStyle: { color: '#fff', width: 1.5 } },
        splitLine: { distance: -18, length: 14, lineStyle: { color: '#fff', width: 2 } },
        axisLabel: { color: 'rgba(255,255,255,0.4)', distance: 25, fontSize: 10 },
        detail: {
          valueAnimation: true,
          formatter: `{value}%`,
          color: threatColor,
          fontSize: 20,
          fontWeight: 'bold',
          offsetCenter: [0, '70%'],
        },
        data: [{ value: Math.round(threatLevel) }],
      },
    ],
  }), [threatLevel, threatColor]);

  return (
    <Card
      size="small"
      style={{
        background: 'linear-gradient(135deg, #1f1f1f 0%, #1a1a2e 100%)',
        borderColor: threatLevel > 40 ? threatColor : '#424242',
        borderWidth: threatLevel > 40 ? 2 : 1,
      }}
    >
      <div style={{ textAlign: 'center', marginBottom: -10 }}>
        <Text strong style={{ color: 'rgba(255,255,255,0.85)', fontSize: 13 }}>
          THREAT LEVEL
        </Text>
      </div>
      <ReactECharts option={option} style={{ height: 180 }} opts={{ renderer: 'canvas' }} />
      <div style={{ textAlign: 'center', marginTop: -15 }}>
        <Text strong style={{ color: threatColor, fontSize: 16, letterSpacing: 2 }}>
          {threatLabel}
        </Text>
        {attack && (
          <div style={{ marginTop: 4 }}>
            <Text style={{ color: '#f5222d', fontSize: 12 }}>
              Active: {atkType.replace(/_/g, ' ').toUpperCase()}
            </Text>
          </div>
        )}
      </div>
    </Card>
  );
};

export default ThreatGauge;
