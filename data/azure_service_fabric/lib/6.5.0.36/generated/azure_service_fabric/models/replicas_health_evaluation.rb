# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ServiceFabric::V6_5_0_36
  module Models
    #
    # Represents health evaluation for replicas, containing health evaluations
    # for each unhealthy replica that impacted current aggregated health state.
    # Can be returned when evaluating partition health and the aggregated
    # health state is either Error or Warning.
    #
    class ReplicasHealthEvaluation < HealthEvaluation

      include MsRestAzure


      def initialize
        @Kind = "Replicas"
      end

      attr_accessor :Kind

      # @return [Integer] Maximum allowed percentage of unhealthy replicas per
      # partition from the ApplicationHealthPolicy.
      attr_accessor :max_percent_unhealthy_replicas_per_partition

      # @return [Integer] Total number of replicas in the partition from the
      # health store.
      attr_accessor :total_count

      # @return [Array<HealthEvaluationWrapper>] List of unhealthy evaluations
      # that led to the aggregated health state. Includes all the unhealthy
      # ReplicaHealthEvaluation that impacted the aggregated health.
      attr_accessor :unhealthy_evaluations


      #
      # Mapper for ReplicasHealthEvaluation class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'Replicas',
          type: {
            name: 'Composite',
            class_name: 'ReplicasHealthEvaluation',
            model_properties: {
              aggregated_health_state: {
                client_side_validation: true,
                required: false,
                serialized_name: 'AggregatedHealthState',
                type: {
                  name: 'String'
                }
              },
              description: {
                client_side_validation: true,
                required: false,
                serialized_name: 'Description',
                type: {
                  name: 'String'
                }
              },
              Kind: {
                client_side_validation: true,
                required: true,
                serialized_name: 'Kind',
                type: {
                  name: 'String'
                }
              },
              max_percent_unhealthy_replicas_per_partition: {
                client_side_validation: true,
                required: false,
                serialized_name: 'MaxPercentUnhealthyReplicasPerPartition',
                type: {
                  name: 'Number'
                }
              },
              total_count: {
                client_side_validation: true,
                required: false,
                serialized_name: 'TotalCount',
                type: {
                  name: 'Number'
                }
              },
              unhealthy_evaluations: {
                client_side_validation: true,
                required: false,
                serialized_name: 'UnhealthyEvaluations',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'HealthEvaluationWrapperElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'HealthEvaluationWrapper'
                      }
                  }
                }
              }
            }
          }
        }
      end
    end
  end
end
