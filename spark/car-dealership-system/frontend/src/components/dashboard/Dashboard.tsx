import React from 'react';
import {
  Grid,
  Paper,
  Typography,
  Box,
  Card,
  CardContent,
  Avatar,
} from '@mui/material';
import {
  TrendingUp,
  DirectionsCar,
  AttachMoney,
  People,
} from '@mui/icons-material';
import { Line, Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

const Dashboard: React.FC = () => {
  // Sample data - will be replaced with real API calls
  const stats = [
    {
      title: 'Total Cars',
      value: '247',
      change: '+12%',
      icon: <DirectionsCar />,
      color: '#1976d2',
    },
    {
      title: 'Sales This Month',
      value: '34',
      change: '+8%',
      icon: <TrendingUp />,
      color: '#2e7d32',
    },
    {
      title: 'Revenue',
      value: '$1.2M',
      change: '+15%',
      icon: <AttachMoney />,
      color: '#ed6c02',
    },
    {
      title: 'Customers',
      value: '1,247',
      change: '+23%',
      icon: <People />,
      color: '#9c27b0',
    },
  ];

  const salesData = {
    labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
    datasets: [
      {
        label: 'Sales',
        data: [30, 45, 28, 52, 34, 67],
        borderColor: '#1976d2',
        backgroundColor: 'rgba(25, 118, 210, 0.1)',
        tension: 0.4,
      },
    ],
  };

  const inventoryData = {
    labels: ['Available', 'Sold', 'Pending', 'Service'],
    datasets: [
      {
        data: [180, 34, 15, 18],
        backgroundColor: ['#2e7d32', '#1976d2', '#ed6c02', '#d32f2f'],
        borderWidth: 0,
      },
    ],
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom sx={{ color: 'white', mb: 4 }}>
        Dashboard Overview
      </Typography>
      
      <Grid container spacing={3}>
        {/* Stats Cards */}
        {stats.map((stat, index) => (
          <Grid item xs={12} sm={6} md={3} key={index}>
            <Card 
              sx={{ 
                background: 'linear-gradient(45deg, #1a1a1a 30%, #2a2a2a 90%)',
                border: '1px solid #333',
              }}
            >
              <CardContent>
                <Box display="flex" alignItems="center" justifyContent="space-between">
                  <Box>
                    <Typography color="textSecondary" gutterBottom variant="body2">
                      {stat.title}
                    </Typography>
                    <Typography variant="h4" sx={{ color: 'white' }}>
                      {stat.value}
                    </Typography>
                    <Typography variant="body2" sx={{ color: '#4caf50' }}>
                      {stat.change} from last month
                    </Typography>
                  </Box>
                  <Avatar sx={{ bgcolor: stat.color, width: 56, height: 56 }}>
                    {stat.icon}
                  </Avatar>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}

        {/* Sales Chart */}
        <Grid item xs={12} md={8}>
          <Paper 
            sx={{ 
              p: 3, 
              background: '#1a1a1a',
              border: '1px solid #333',
            }}
          >
            <Typography variant="h6" gutterBottom sx={{ color: 'white' }}>
              Monthly Sales Trend
            </Typography>
            <Line data={salesData} />
          </Paper>
        </Grid>

        {/* Inventory Distribution */}
        <Grid item xs={12} md={4}>
          <Paper 
            sx={{ 
              p: 3, 
              background: '#1a1a1a',
              border: '1px solid #333',
              height: 400,
              display: 'flex',
              flexDirection: 'column',
            }}
          >
            <Typography variant="h6" gutterBottom sx={{ color: 'white' }}>
              Inventory Status
            </Typography>
            <Box sx={{ flexGrow: 1, display: 'flex', alignItems: 'center' }}>
              <Doughnut data={inventoryData} />
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;
